// SPDX-License-Identifier: GPL-2.0
/*
 * TDX guest vTPM driver
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/acpi.h>
#include <linux/set_memory.h>
#include <crypto/aead.h>
#include <acpi/actbl2.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

#include "tpm.h"

#define TDX_TPM_DEV			"tpm"

#define TDX_TPM_MSG_LEN			(2 * PAGE_SIZE)
#define TPM_SEND_COMMAND		8

/* TDX TPM ACPI defines */
#define TDX_SESS_INFO_VER		0x0100
#define TDX_SESS_PROT_SPDM		0x0

/* TDX Session Info defines */
#define TDX_SESS_SPDM_TRANS_VER		0x1000
#define TDX_AEAD_ALGO_AES_256		0x01
#define TDX_AEAD_AES_256_IV_LEN		12
#define TDX_AEAD_AES_256_KEY_LEN	32
#define TDX_AEAD_AES_256_ATAG_LEN	16
#define TDX_AEAD_AAD_LEN		14

/* TDX SPDM defines */
#define TDX_SPDM_MSG_VER		0x01
#define TDX_SPDM_MSG_TYPE_DSP0274	0x01
#define TDX_SPDM_MSG_TYPE_DSP0277	0x02
#define TDX_SPDM_MSG_TYPE_TPM		0x03
#define TDX_SPDM_MSG_TYPE_MIG		0x04

#define TDVMCALL_TPM_SEND_MSG		0x01
#define TDVMCALL_TPM_RECV_MSG		0x02
#define TDVMCALL_TPM_CMD_TIMEOUT	5000
#define TDVMCALL_SERVICE_TIMEOUT	6000
#define TDVMCALL_TPM_RESP_INFLIGHT	0xFFFFFFFF

#define size_from(type, mem) (sizeof(type) - offsetofend(type, mem))

#define MSG_REQ_SIZE_FROM(mem) size_from(struct tdx_tpm_msg_req, mem)
#define MSG_RESP_SIZE_FROM(mem) size_from(struct tdx_tpm_msg_resp, mem)

/**
 * struct spdm_msg_hdr - SPDM secure session message header
 * @mlen: Length of message including mver and mtype.
 * @mver: SPDM message version number.
 * @mtype: Type of the SPDM message.
 * 	   1 – DSP0274 SPDM message.
 * 	   2 – DSP0277 Secured SPDM message.
 */
struct spdm_msg_hdr {
	u16 mlen;
	u8 mver;
	u8 mtype;
} __packed;

/**
 * struct spdm_aad - Secure session message AEAD assosiated data. It is the
 * 		     concatenation of the following fields in this order
 * @sess_id: Session ID.
 * @seq_no: Sequence Number.
 * @tlen: Length of the plain or ciper text, Random data and MAC.
 */
struct spdm_aad {
	u32 sess_id;
	u64 seq_no;
	u16 tlen;
} __packed;

/**
 * struct spdm_data - Secure session message application data.
 * @dlen: Length of the application data.
 * @data_type: Type of the application data.
 * 	       1 – DSP0274 SPDM message.
 * 	       3 – TPM message.
 * 	       4 – Migration message.
 * @data: Application data.
 */
struct spdm_data {
	u16 dlen;
	u8 data_type;
	u8 data[];
} __packed;


/**
 * struct tdx_tpm_msg_req - TDX TPM message request format.
 * @guid: A unique GUID to identify the TDVMCALL service.
 * @buf_len: Length of the request buffer.
 * @rsvd1: Reserved for future use.
 * @service_ver: Version of TPM TDVMCALL command.
 * @service_cmd: TPM TDVMCALL command
 * 		 TDVMCALL_TPM_SEND_MSG - 0x01
 * 		 TDVMCALL_TPM_RECV_MSG - 0x02
 * @rsvd2: Reserved for future use.
 * @spdm: SPDM Message header.
 * @aad: SPDM AAD data.
 * @app_data: SPDM application data.
 *
 * For more details, refer to TDX vTPM specification, r1.0, section titled
 * "SPDM Secure Session Message Format".
 */
struct tdx_tpm_msg_req {
	/* TDVMCALL service request header */
	u8 guid[16];
	u32 buf_len;
	u32 rsvd1;

	/* TDVMCALL TPM Command Buffer */
	u8 service_ver;
	u8 service_cmd;
	u8 rsvd2[2];

	/* SPDM Message */
	struct spdm_msg_hdr spdm;
	struct spdm_aad aad;
	struct spdm_data app_data;
} __packed;

/**
 * struct tdx_tpm_msg_resp - TDX TPM message response format.
 * @guid: A unique GUID to identify the TDVMCALL service.
 * @buf_len: Length of the response buffer.
 * @rsvd1: Reserved for future use.
 * @service_ver: Version of TPM TDVMCALL command.
 * @service_cmd: TPM TDVMCALL command
 * 		 TDVMCALL_TPM_SEND_MSG - 0x01
 * 		 TDVMCALL_TPM_RECV_MSG - 0x02
 * @rsvd2: Reserved for future use.
 * @spdm: SPDM Message header.
 * @aad: SPDM AAD data.
 * @app_data: SPDM application data.
 *
 * For more details, refer to TDX vTPM specification, r1.0, section titled
 * "SPDM Secure Session Message Format".
 */
struct tdx_tpm_msg_resp {
	/* TDVMCALL service response header */
	u8 guid[16];
	u32 buf_len;
	u32 tdvmcall_status;

	/* TDVMCALL TPM Command Buffer response */
	u8 service_ver;
	u8 service_cmd;
	u8 service_cmd_status;
	u8 rsvd;

	/* SPDM Message */
	struct spdm_msg_hdr spdm;
	struct spdm_aad aad;
	struct spdm_data app_data;
} __packed;

/**
 * struct tdx_service_node - Service node used to track active VMM
 * 			     TDVMCALL service request.
 * @valid: Flag to check validity of the TPM request.
 * @compl: Completion object to track completion of service request.
 */
struct tdx_service_node
{
	bool valid;
	struct completion compl;
};

/**
 * struct tdx_tpm_crypto - Crypto parameters used in SPDM message
 * 			   encryption/decryption.
 * @init_iv: Initial IV value extracted from the TDTK ACPI table.
 * @new_iv: Buffer used to track the new IV.
 * @key: Key used to encrypt or decrypt SPDM message, extracted
 *	 from TDTK ACPI table.
 * @atag: Authentication TAG used in SPDM encryption/decryption.
 * @key_len: Length of the key.
 * @iv_len: Length of the IV.
 * @atag_len: Length of the ATAG.
 * @seq_no: Sequence number used in TPM SPDM communication.
 * @tfm: Crypto TFM object.
 */
struct tdx_tpm_crypto {
	u8 *init_iv;
	u8 *new_iv;
	u8 *key;
	u8 *atag;
	u32 key_len;
	u32 iv_len;
	u32 atag_len;
	u64 seq_no;
	struct crypto_aead *tfm;
};

/**
 * struct tdx_tpm_session - TPM SPDM session object.
 * @ver: ACPI TDTK table session info version.
 * @algo: AEAD alogorithm used in SPDM.
 * @sess_id: SPDM Session ID.
 * @send_crypto: Crypto object used for TPM CMD messages.
 * @recv_crypto: Crypto object used for TPM receive messages.
 */
struct tdx_tpm_session {
	u16 ver;
	u16 algo;
	u32 sess_id;
	struct tdx_tpm_crypto send_crypto;
	struct tdx_tpm_crypto recv_crypto;
};

/**
 * struct tdx_tpm_dev - TPM device object.
 * @chip: Reference to TPM Chip.
 * @req: Buffer used to send TPM request.
 * @resp: Buffer used to receive TPM response.
 * @session: ACPI TDTK session info.
 * @service: Service node used to save active TPM request.
 * @tpm_req_lock: Lock to streamline TPM requests.
 * @dev: Pointer to device struct.
 * @msg_len: TPM buffer request and response length.
 */
struct tdx_tpm_dev {
	struct tpm_chip *chip;
	struct tdx_tpm_msg_req *req;
	struct tdx_tpm_msg_resp *resp;
	struct tdx_tpm_session session;
	struct tdx_service_node service;
	struct mutex tpm_req_lock;
	struct device *dev;
	u32 msg_len;
};

static guid_t tpm_guid = GUID_INIT(0x64590793, 0x7852, 0x4e52, 0xbe, 0x45, 0xcd,
				   0xbb, 0x11, 0x6f, 0x20, 0xf3);

static u8 tpm_atag[] = { 0xDE, 0xAD, 0xBE, 0xAF, 0xDE, 0xAD, 0xBA, 0xBE,
			 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0x2B, 0xAD};

/* Callback handler used in TDX VMM event notification */
static int service_cb_handler(void *dev_id)
{
	struct tdx_tpm_dev *tdev = dev_id;

	if (tdev->service.valid && tdev->resp->tdvmcall_status !=
	    TDVMCALL_TPM_RESP_INFLIGHT)
		complete(&tdev->service.compl);

	return 0;
}

/*
 * enc_dec_msg() - Encrypt the data in sbuf and copy the result to dbuf.
 * @tdev - Reference to struct tdx_tpm_dev object.
 * @crypto - struct tdx_tpm_crypto object used in encryption/decryption
 * 	     process.
 * @aad - Associated data used in AEAD encryption.
 * @sbuf - Soure buffer with data (plain text or ciper text).
 * @dbuf - Destination buffer to store the result.
 * @len - Length of the plain text or ciper text from @src.
 * @cryptlen - Number of bytes to process from @src (Including ATAG).
 * @enc - 1 for encryption and 0 for decryption.
 */
static int enc_dec_msg(struct tdx_tpm_dev *tdev,
		       struct tdx_tpm_crypto *crypto,
		       u8 *aad, u8 *sbuf, u8 *dbuf, size_t len,
		       size_t new_len, bool enc)
{
	struct scatterlist src[3], dst[3];
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	int ret;

	req = aead_request_alloc(crypto->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	sg_init_table(src, 3);
	sg_set_buf(&src[0], aad, TDX_AEAD_AAD_LEN);
	sg_set_buf(&src[1], sbuf, len);
	sg_set_buf(&src[2], &sbuf[len], crypto->atag_len);

	sg_init_table(dst, 3);
	sg_set_buf(&dst[0], aad, TDX_AEAD_AAD_LEN);
	sg_set_buf(&dst[1], dbuf, len);
	sg_set_buf(&dst[2], &dbuf[len], crypto->atag_len);

	aead_request_set_ad(req, TDX_AEAD_AAD_LEN);
	aead_request_set_tfm(req, crypto->tfm);
	aead_request_set_callback(req, 0, crypto_req_done, &wait);

	aead_request_set_crypt(req, src, dst, new_len, crypto->new_iv);
	ret = crypto_wait_req(enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);

	aead_request_free(req);

	return ret;
}

static void spdm_recalc_iv(struct tdx_tpm_crypto *crypto)
{
	u32 i;

	memset(crypto->new_iv, 0, crypto->iv_len);
	memcpy(crypto->new_iv, &crypto->seq_no, sizeof(crypto->seq_no));

	for (i = 0; i < crypto->iv_len; i++)
		crypto->new_iv[i] = crypto->init_iv[i] ^ crypto->new_iv[i];
}

static int tdx_tpm_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	struct tdx_tpm_dev *tdev = dev_get_drvdata(&chip->dev);
	struct tdx_tpm_msg_req *req = tdev->req;
	struct tdx_tpm_msg_resp *resp = tdev->resp;
	struct tdx_tpm_crypto *crypto = &tdev->session.send_crypto;
	u32 data_len, tot_data_len = len + crypto->atag_len;
	int ret;

	if (len > tdev->msg_len - sizeof(*req))
		return -EINVAL;

	/* Use locking to streamline TPM requests to the VMM */
	mutex_lock(&tdev->tpm_req_lock);

	memset(req, 0, tdev->msg_len);
	memset(resp, 0, tdev->msg_len);

	/* Initialize TDVMCALL header */
	memcpy(req->guid, &tpm_guid, sizeof(tpm_guid));
	req->buf_len = sizeof(*req) + tot_data_len;
	req->service_ver = 0;
	req->service_cmd = TDVMCALL_TPM_SEND_MSG;

	/* Initialize SPDM msg header */
	req->spdm.mver = TDX_SPDM_MSG_VER;
	req->spdm.mtype = TDX_SPDM_MSG_TYPE_DSP0277;
	req->spdm.mlen = MSG_REQ_SIZE_FROM(spdm.mlen) + tot_data_len;

	/* Initialize AAD header */
	req->aad.tlen = MSG_REQ_SIZE_FROM(aad.tlen) + tot_data_len;
	req->aad.seq_no = crypto->seq_no;
	req->aad.sess_id = tdev->session.sess_id;

	/* Initialize SPDM data header */
	req->app_data.dlen = MSG_REQ_SIZE_FROM(app_data.dlen) + len;
	req->app_data.data_type = TDX_SPDM_MSG_TYPE_TPM;

	/* Initialize src buf */
	memcpy(req->app_data.data, buf, len);
	memcpy(&req->app_data.data[len], crypto->atag, crypto->atag_len);
	data_len = sizeof(req->app_data) + len;

	/* Initialize resp buf */
	memcpy(resp->guid, &tpm_guid, sizeof(tpm_guid));
	resp->buf_len = tdev->msg_len;
	resp->service_ver = 0;
	resp->service_cmd = TDVMCALL_TPM_SEND_MSG;
	resp->service_cmd_status = 0;
	resp->tdvmcall_status = TDVMCALL_TPM_RESP_INFLIGHT;

	/* Use request seq_no to recalculate IV */
	spdm_recalc_iv(crypto);

	/* Encrypt the TPM SPDM message */
	ret = enc_dec_msg(tdev, crypto, (u8 *)&req->aad, (u8 *)&req->app_data,
			  (u8 *)&req->app_data, data_len, data_len, 1);
	if (ret) {
		dev_err(tdev->dev, "Send msg: encryption failed\n");
		goto send_msg_failed;
	}

	/* Increment the seq_no */
	crypto->seq_no++;

	/* Mark the service valid to track the active request */
	reinit_completion(&tdev->service.compl);
	tdev->service.valid = true;

	ret = tdx_hcall_service((u8 *)req, (u8 *)resp, TDVMCALL_TPM_CMD_TIMEOUT);
	if (ret) {
		dev_err(tdev->dev, "Send msg: TDVMCALL failed");
		goto send_msg_failed;
	}

	/* Wait for the event notification from VMM */
	wait_for_completion_timeout(&tdev->service.compl,
			msecs_to_jiffies(TDVMCALL_SERVICE_TIMEOUT));

	dev_dbg(tdev->dev, "Send msg: TDVMCALL status:%x Cmd status:%x\n",
		resp->tdvmcall_status, resp->service_cmd_status);

	if (resp->tdvmcall_status || resp->service_cmd_status) {
		dev_err(tdev->dev, "Send msg: TDVMCALL status:%x Cmd status:%x\n",
			resp->tdvmcall_status, resp->service_cmd_status);
		ret = -EIO;
		goto send_msg_failed;
	}

	tdev->service.valid = false;

	mutex_unlock(&tdev->tpm_req_lock);

	return 0;

send_msg_failed:
	tdev->service.valid = false;
	mutex_unlock(&tdev->tpm_req_lock);
	return ret;
}

static int tdx_tpm_recv(struct tpm_chip *chip, u8 *buf, size_t len)
{
	struct tdx_tpm_dev *tdev = dev_get_drvdata(&chip->dev);
	struct tdx_tpm_msg_req *req = tdev->req;
	struct tdx_tpm_msg_resp *resp = tdev->resp;
	struct tdx_tpm_crypto *crypto = &tdev->session.recv_crypto;
	int msg_size, ret;

	if (len > tdev->msg_len - sizeof(*req))
		return -EINVAL;

	/* Use locking to streamline TPM requests to the VMM */
	mutex_lock(&tdev->tpm_req_lock);

	memset(req, 0, tdev->msg_len);
	memset(resp, 0, tdev->msg_len);

	/* Initialize req buf */
	memcpy(req->guid, &tpm_guid, sizeof(tpm_guid));
	req->buf_len = sizeof(*req) - MSG_REQ_SIZE_FROM(rsvd2);
	req->service_ver = 0;
	req->service_cmd = TDVMCALL_TPM_RECV_MSG;

	/* Initialize resp buf */
	memcpy(resp->guid, &tpm_guid, sizeof(tpm_guid));
	resp->buf_len = tdev->msg_len;
	resp->service_ver = 0;
	resp->service_cmd = TDVMCALL_TPM_RECV_MSG;
	resp->service_cmd_status = 0;
	resp->tdvmcall_status = TDVMCALL_TPM_RESP_INFLIGHT;

	/* Mark the service valid to track the active request */
	reinit_completion(&tdev->service.compl);
	tdev->service.valid = true;

	ret = tdx_hcall_service((u8 *)req, (u8 *)resp, TDVMCALL_TPM_CMD_TIMEOUT);
	if (ret) {
		dev_err(tdev->dev, "Recv msg: TDVMCALL failed");
		goto recv_msg_failed;
	}

	/* Wait for the event notification from VMM */
	wait_for_completion_timeout(&tdev->service.compl,
			msecs_to_jiffies(TDVMCALL_SERVICE_TIMEOUT));

	dev_dbg(tdev->dev, "Recv msg: TDVMCALL status:%x Cmd status:%x\n",
		resp->tdvmcall_status, resp->service_cmd_status);

	if (resp->tdvmcall_status || resp->service_cmd_status) {
		dev_err(tdev->dev, "Recv msg: TDVMCALL status:%x Cmd status:%x\n",
			resp->tdvmcall_status, resp->service_cmd_status);
		ret = -EIO;
		goto recv_msg_failed;
	}

	/* Use request seq_no to recalculate IV */
	spdm_recalc_iv(crypto);

	ret = enc_dec_msg(tdev, crypto, (u8 *)&resp->aad, (u8 *)&resp->app_data,
			  (u8 *)&resp->app_data, resp->aad.tlen - crypto->atag_len,
			  resp->aad.tlen, 0);
	if (ret) {
		dev_err(tdev->dev, "Recv msg: decryption failed %d\n", ret);
		goto recv_msg_failed;
	}

	/* Increment the seq_no */
	crypto->seq_no++;

	msg_size = resp->app_data.dlen - sizeof(resp->app_data.data_type);

	if (msg_size < 0) {
		dev_err(tdev->dev, "Recv msg: Invalid resp size:%d\n", msg_size);
		ret = msg_size;
		goto recv_msg_failed;
	}

	if (len < msg_size) {
		dev_err(tdev->dev, "Recv msg: Data size is large %d > %ld\n",
			msg_size, len);
		ret = -E2BIG;
		goto recv_msg_failed;
	}

	memcpy(buf, resp->app_data.data, msg_size);

	tdev->service.valid = false;
	mutex_unlock(&tdev->tpm_req_lock);

	return msg_size;

recv_msg_failed:
	tdev->service.valid = false;
	mutex_unlock(&tdev->tpm_req_lock);
	return ret;
}

static struct tpm_class_ops tpm_chip_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.send = tdx_tpm_send,
	.recv = tdx_tpm_recv,
};

/* Initialize the AES256 crypto object */
static int tdx_aes_256_init(struct tdx_tpm_crypto *crypto,
			    u8 *key, u32 key_len, u8 *iv, u32 iv_len,
			    u32 atag_len, u64 seq_no)
{
	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm))
		return PTR_ERR(crypto->tfm);

	crypto->key = kmalloc(key_len, GFP_KERNEL);
	if (!crypto->key)
		goto err_free_crypto;

	memcpy(crypto->key, key, key_len);
	crypto->key_len = key_len;

	if (crypto_aead_setkey(crypto->tfm, key, key_len))
	       goto err_free_key;

	if (crypto_aead_ivsize(crypto->tfm) != iv_len)
		goto err_free_key;

	crypto->iv_len = iv_len;

	crypto->init_iv = kmalloc(crypto->iv_len, GFP_KERNEL);
	if (!crypto->init_iv)
		goto err_free_key;

	if (iv)
		memcpy(crypto->init_iv, iv, crypto->iv_len);

	crypto->new_iv = kmalloc(crypto->iv_len, GFP_KERNEL);
	if (!crypto->new_iv)
		goto err_free_init_iv;

	if (crypto_aead_authsize(crypto->tfm) > atag_len) {
		if (crypto_aead_setauthsize(crypto->tfm, atag_len))
			goto err_free_iv;
	}

	crypto->atag_len = crypto_aead_authsize(crypto->tfm);

	crypto->atag = kmalloc(crypto->atag_len, GFP_KERNEL);
	if (!crypto->atag)
		goto err_free_iv;

	memcpy(crypto->atag, tpm_atag, crypto->atag_len);

	crypto->seq_no = seq_no;

	return 0;

err_free_iv:
	kfree(crypto->new_iv);
err_free_init_iv:
	kfree(crypto->init_iv);
err_free_key:
	kfree(crypto->key);
err_free_crypto:
	crypto_free_aead(crypto->tfm);

	return -EIO;
}

static void tdx_aes_256_deinit(struct tdx_tpm_crypto *crypto)
{
	crypto_free_aead(crypto->tfm);
	kfree(crypto->init_iv);
	kfree(crypto->new_iv);
	kfree(crypto->atag);
}

static void tdx_tpm_deinit_session(struct tdx_tpm_dev *tdev)
{
	tdx_aes_256_deinit(&tdev->session.send_crypto);
	tdx_aes_256_deinit(&tdev->session.recv_crypto);
}

/* Parse TDTK ACPI table and initialize the session object */
static int tdx_tpm_init_session(struct tdx_tpm_dev *tdev)
{
	struct tdx_tpm_session *info = &tdev->session;
	struct acpi_tdtk_aes_256_gcm *aes_gcm;
	struct acpi_tdtk_spdm *spdm;
	struct acpi_table_tdtk *tdtk;
	void __iomem *addr;
	acpi_status status;
	int ret;

	status = acpi_get_table(ACPI_SIG_TDTK, 1,
				(struct acpi_table_header **)&tdtk);
	if (ACPI_FAILURE(status) || tdtk->header.length < sizeof(*tdtk)) {
		dev_err(tdev->dev, FW_BUG "Failed to get TDTK ACPI table\n");
		return -EINVAL;
	}

	if (tdtk->version != TDX_SESS_INFO_VER ||
	    tdtk->protocol != TDX_SESS_PROT_SPDM) {
		dev_err(tdev->dev, "Unsupported TDTK protocol or version\n");
		ret = -EINVAL;
		goto put_table;
	}

	addr = ioremap(tdtk->info_address, tdtk->info_len);
	if (!addr) {
		dev_err(tdev->dev, "Failed to remap SPDM table %llx\n",
			tdtk->info_address);
		ret = -EINVAL;
		goto put_table;
	}

	spdm = (struct acpi_tdtk_spdm *)addr;
	aes_gcm = (struct acpi_tdtk_aes_256_gcm *)(addr + sizeof(*spdm));

	if (spdm->trans_ver != TDX_SESS_SPDM_TRANS_VER ||
	    spdm->aead_algo != TDX_AEAD_ALGO_AES_256) {
		dev_err(tdev->dev, "Invalid SPDM version or Algo\n");
		goto unmap_addr;
	}

	info->ver = spdm->trans_ver;
	info->algo = spdm->aead_algo;
	info->sess_id = spdm->sess_id;

	ret = tdx_aes_256_init(&info->send_crypto, aes_gcm->req_key,
			       TDX_AEAD_AES_256_KEY_LEN, aes_gcm->req_iv,
			       TDX_AEAD_AES_256_IV_LEN,
			       TDX_AEAD_AES_256_ATAG_LEN, aes_gcm->req_seq);
	if (ret)
		goto unmap_addr;

	ret = tdx_aes_256_init(&info->recv_crypto, aes_gcm->resp_key,
			       TDX_AEAD_AES_256_KEY_LEN, aes_gcm->resp_iv,
			       TDX_AEAD_AES_256_IV_LEN,
			       TDX_AEAD_AES_256_ATAG_LEN, aes_gcm->resp_seq);
	if (ret)
		goto aes_deinit;

	goto unmap_addr;
aes_deinit:
	tdx_aes_256_deinit(&info->send_crypto);
unmap_addr:
	iounmap(addr);
put_table:
	acpi_put_table((struct acpi_table_header *)tdtk);
	return ret;
}

static void free_shared_pages(void *buf, size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;

	set_memory_encrypted((unsigned long)buf, count);

	free_pages_exact(buf, PAGE_ALIGN(len));
}

static void *alloc_shared_pages(size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;
	void *addr;
	int ret;

	addr = alloc_pages_exact(len, GFP_KERNEL);
	if (!addr)
		return NULL;

	ret = set_memory_decrypted((unsigned long)addr, count);
	if (ret) {
		free_pages_exact(addr, PAGE_ALIGN(len));
		return NULL;
	}

	return addr;
}

static void tdx_tpm_free_buf(struct tdx_tpm_dev *tdev)
{
	free_shared_pages((void *)tdev->req, tdev->msg_len);
	free_shared_pages((void *)tdev->resp, tdev->msg_len);
}

static int tdx_tpm_alloc_buf(struct tdx_tpm_dev *tdev)
{
	tdev->msg_len = TDX_TPM_MSG_LEN;

	tdev->req = (struct tdx_tpm_msg_req *)alloc_shared_pages(tdev->msg_len);
	if (!tdev->req)
		goto alloc_failed;

	tdev->resp = (struct tdx_tpm_msg_resp *)alloc_shared_pages(tdev->msg_len);
	if (!tdev->resp)
		goto alloc_failed;

	return 0;

alloc_failed:
	dev_err(tdev->dev, "Buffer allocation failed\n");
	tdx_tpm_free_buf(tdev);
	return -ENOMEM;
}

static int tdx_tpm_probe(struct platform_device *pdev)
{
	struct tdx_tpm_dev *tdev;
	struct tpm_chip *chip;
	int err;

	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	tdev->dev = &pdev->dev;
	mutex_init(&tdev->tpm_req_lock);

	err = tdx_tpm_alloc_buf(tdev);
	if (err)
		goto free_tdev;

	err = tdx_tpm_init_session(tdev);
	if (err)
		goto free_buf;

	init_completion(&tdev->service.compl);

	err = tdx_register_event_irq_cb(service_cb_handler, tdev);
	if (err)
		goto free_session;

	chip = tpmm_chip_alloc(&pdev->dev, &tpm_chip_ops);
	if (IS_ERR(chip)) {
		err = PTR_ERR(chip);
		goto free_cb;
	}

	tdev->chip = chip;
	dev_set_drvdata(&chip->dev, tdev);

	chip->flags |= TPM_CHIP_FLAG_IRQ;
	err = tpm2_probe(chip);
	if (err)
		goto free_cb;

	err = tpm_chip_register(chip);
	if (err)
		goto free_cb;

	dev_info(&pdev->dev, "TDX vTPM %s device\n",
		 (chip->flags & TPM_CHIP_FLAG_TPM2) ? "2.0" : "1.2");

	return 0;

free_cb:
	tdx_unregister_event_irq_cb(service_cb_handler, tdev);
free_session:
	tdx_tpm_deinit_session(tdev);
free_buf:
	tdx_tpm_free_buf(tdev);
free_tdev:
	kfree(tdev);

	return err;
}

static int tdx_tpm_remove(struct platform_device *pdev)
{
	struct tpm_chip *chip = dev_get_drvdata(&pdev->dev);
	struct tdx_tpm_dev *tdev = dev_get_drvdata(&chip->dev);

	tdx_unregister_event_irq_cb(service_cb_handler, tdev);
	tdx_tpm_deinit_session(tdev);
	tdx_tpm_free_buf(tdev);
	tpm_chip_unregister(tdev->chip);
	kfree(tdev);
	return 0;
}

static const struct x86_cpu_id tdx_guest_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_GUEST, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_guest_ids);

static struct platform_driver tdx_tpm_driver = {
	.probe = tdx_tpm_probe,
	.remove = tdx_tpm_remove,
	.driver.name = TDX_TPM_DEV,
};
module_platform_driver(tdx_tpm_driver);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX vTPM Driver");
MODULE_LICENSE("GPL");
