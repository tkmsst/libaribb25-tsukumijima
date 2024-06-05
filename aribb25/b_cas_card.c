#include "b_cas_card.h"
#include "b_cas_card_error_code.h"
#include "b_cas_crypt.h"

#include <stdlib.h>
#include <string.h>

#include <math.h>

#if defined(_WIN32)
#  include <tchar.h>
#  include <windows.h>
#  include <winscard.h>
#  define CONF ".ini"
#else
#  include <dlfcn.h>
#  if defined(DEBUG)
#    include <stdio.h>
#  endif
#  define TCHAR char
#  define _T(x) x
#  define _tfopen fopen
#  define __USE_GNU
#  define CONF ".conf"
#endif

#if defined(_WIN32)
	// ref: https://stackoverflow.com/a/6924293/17124142
	EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#endif

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 inner structures
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define KEY_MAX 128

typedef struct {
	uint8_t  broadcast_group_id;
	uint8_t  work_key_id;
	uint64_t work_key;
} WORK_KEY_TABLE;

typedef struct {
	WORK_KEY_TABLE    *table[KEY_MAX];
	B_CAS_INIT_STATUS  stat;
} B_CAS_CARD_PRIVATE_DATA;

typedef struct {
	uint8_t  protocol_number;
	uint8_t  broadcast_group_id;
	uint8_t  work_key_id;
	uint8_t  scramble_key[16];
} ECM_TABLE;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 constant values
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static const char LIB_DIR[] = "/usr/local/lib/";

static const uint8_t BCAS_SYSTEM_KEY[] = {
	0x36, 0x31, 0x04, 0x66, 0x4b, 0x17, 0xea, 0x5c,
	0x32, 0xdf, 0x9c, 0xf5, 0xc4, 0xc3, 0x6c, 0x1b,
	0xec, 0x99, 0x39, 0x21, 0x68, 0x9d, 0x4b, 0xb7,
	0xb7, 0x4e, 0x40, 0x84, 0x0d, 0x2e, 0x7d, 0x98
};

static const uint8_t BCAS_INIT_CBC[] = {
	0xfe, 0x27, 0x19, 0x99, 0x19, 0x69, 0x09, 0x11
};

static const int32_t BCAS_CA_SYSTEM_ID = 0x0005;

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prototypes (interface method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_card(void *bcas);
static int init_b_cas_card(void *bcas);
static int get_init_status_b_cas_card(void *bcas, B_CAS_INIT_STATUS *stat);
static int get_id_b_cas_card(void *bcas, B_CAS_ID *dst);
static int get_pwr_on_ctrl_b_cas_card(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst);
static int proc_ecm_b_cas_card(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len);
static int proc_emm_b_cas_card(void *bcas, uint8_t *src, int len);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 global function implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
B_CAS_CARD *create_b_cas_card(void)
{
	int n;

	B_CAS_CARD *r;
	B_CAS_CARD_PRIVATE_DATA *prv;

	n = sizeof(B_CAS_CARD) + sizeof(B_CAS_CARD_PRIVATE_DATA);
	prv = (B_CAS_CARD_PRIVATE_DATA *)calloc(1, n);
	if(prv == NULL){
		return NULL;
	}

	r = (B_CAS_CARD *)(prv+1);

	r->private_data = prv;

	r->release = release_b_cas_card;
	r->init = init_b_cas_card;
	r->get_init_status = get_init_status_b_cas_card;
	r->get_id = get_id_b_cas_card;
	r->get_pwr_on_ctrl = get_pwr_on_ctrl_b_cas_card;
	r->proc_ecm = proc_ecm_b_cas_card;
	r->proc_emm = proc_emm_b_cas_card;

	return r;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 function prototypes (private method)
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas);
static void teardown(B_CAS_CARD_PRIVATE_DATA *prv);
static int load_work_key_table(B_CAS_CARD_PRIVATE_DATA *prv, TCHAR *path);
static uint64_t pickup_hex(char **pp, int n);
static int decode_ecm(B_CAS_CARD_PRIVATE_DATA *prv, uint8_t *scramble_key, const ECM_TABLE *in)

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 interface method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void release_b_cas_card(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		/* do nothing */
		return;
	}

	teardown(prv);
	free(prv);
}

static int init_b_cas_card(void *bcas)
{
	int n;
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if(prv == NULL){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	teardown(prv);

#if defined(_WIN32)
	// この dll/exe と拡張子なしファイル名が同じ conf ファイルのパスを取得
	TCHAR conf_file_path[MAX_PATH];
	GetModuleFileName((HINSTANCE)&__ImageBase, conf_file_path, MAX_PATH);
	_tcscpy_s(_tcsrchr(conf_file_path, _T('.')), MAX_PATH - _tcslen(_T(CONF)) - 1, _T(CONF));

	OutputDebugString(_T("libaribb25: conf file path:"));
	OutputDebugString(conf_file_path);
#else
	Dl_info info;
	char conf_file_path[PATH_MAX];
	if(dladdr((void *)init_b_cas_card, &info) == 0){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}
	strncpy(conf_file_path, info.dli_fname, PATH_MAX);
	conf_file_path[PATH_MAX - strlen(CONF) - 1] = '\0';
	strcat(conf_file_path, CONF);
#endif
	n = load_work_key_table(prv, conf_file_path);
	if(n < 0){
		return n;
	}

	memcpy(prv->stat.system_key, BCAS_SYSTEM_KEY, 32);
	memcpy(prv->stat.init_cbc, BCAS_INIT_CBC, 8);
	prv->stat.bcas_card_id = 0;
	prv->stat.card_status = 0;
	prv->stat.ca_system_id = BCAS_CA_SYSTEM_ID;

	return 0;
}

static int get_init_status_b_cas_card(void *bcas, B_CAS_INIT_STATUS *stat)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (stat == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->stat.ca_system_id == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memcpy(stat, &(prv->stat), sizeof(B_CAS_INIT_STATUS));

	return 0;
}

static int get_id_b_cas_card(void *bcas, B_CAS_ID *dst)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (dst == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->stat.ca_system_id == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memset(dst, 0, sizeof(B_CAS_ID));

	return 0;
}

static int get_pwr_on_ctrl_b_cas_card(void *bcas, B_CAS_PWR_ON_CTRL_INFO *dst)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) || (dst == NULL) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->stat.ca_system_id == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	memset(dst, 0, sizeof(B_CAS_PWR_ON_CTRL_INFO));

	return 0;
}

static int proc_ecm_b_cas_card(void *bcas, B_CAS_ECM_RESULT *dst, uint8_t *src, int len)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) ||
			(dst == NULL) ||
			(src == NULL) ||
			(len < 1) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->stat.ca_system_id == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	if (decode_ecm(prv, dst->scramble_key, (ECM_TABLE *)src) < 0) {
		return B_CAS_CARD_ERROR_TRANSMIT_FAILED;
	}
	dst->return_code = 0x0800;

	return 0;
}

static int proc_emm_b_cas_card(void *bcas, uint8_t *src, int len)
{
	B_CAS_CARD_PRIVATE_DATA *prv;

	prv = private_data(bcas);
	if( (prv == NULL) ||
			(src == NULL) ||
			(len < 1) ){
		return B_CAS_CARD_ERROR_INVALID_PARAMETER;
	}

	if(prv->stat.ca_system_id == 0){
		return B_CAS_CARD_ERROR_NOT_INITIALIZED;
	}

	return 0;
}

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 private method implementation
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static B_CAS_CARD_PRIVATE_DATA *private_data(void *bcas)
{
	B_CAS_CARD_PRIVATE_DATA *r;
	B_CAS_CARD *p;

	p = (B_CAS_CARD *)bcas;
	if(p == NULL){
		return NULL;
	}

	r = (B_CAS_CARD_PRIVATE_DATA *)(p->private_data);
	if( ((void *)(r+1)) != ((void *)p) ){
		return NULL;
	}

	return r;
}

static void teardown(B_CAS_CARD_PRIVATE_DATA *prv)
{
	int i;

	prv->stat.ca_system_id = 0;

	for(i=0;i<KEY_MAX;i++){
		WORK_KEY_TABLE *p = prv->table[i];
		if(p == NULL){
			break;
		}
		free(p);
	}
}

static int load_work_key_table(B_CAS_CARD_PRIVATE_DATA *prv, TCHAR *path);
{
	int i = 0;
	char buf[256];
	uint8_t gid

	fp = _tfopen(path, _T("r"));
	if(fp == NULL){
		return B_CAS_CARD_ERROR_NO_SMART_CARD_READER;
	}

	while(i < KEY_MAX){
		if(fgets(buf, sizeof(buf), fp) == NULL){
			break;
		}

		char *p = buf;
		gid = pickup_hex(&p, 2) & 0xff;
		if(gid == 0){
			continue;
		}
		prv->table[i] = (WORK_KEY_TABLE *)malloc(sizeof(WORK_KEY_TABLE));
		if(prv->table[i] == NULL){
			fclose(fp);
			return B_CAS_CARD_ERROR_NO_ENOUGH_MEMORY;
		}
		prv->table[i]->broadcast_group_id = gid;
		prv->table[i]->work_key_id = pickup_hex(&p, 2) & 0xff;
		prv->table[i]->work_key = pickup_hex(&p, 16);
		i++;
	}
	if(i < KEY_MAX){
		prv->table[i] = NULL;
	}

	fclose(fp);

	return 0;
}

static uint64_t pickup_hex(char **pp, int n)
{
	uint64_t x = 0;
	char *p = *pp;

	while(*p && n-- > 0){
		if(*p == '\0'){
			return 0;
		}
		int c = *p++;
		if(c < '0' || (c > '9' && c < 'A') || (c > 'F' && c < 'a') || c > 'f'){
			continue;
		}
		c |= 'a' - 'A'; /* to lower case */
		c -= '0';
		if(c > 9){
			c -= 'a' - ('0' + 10);
		}
		x <<= 4;
		x |= c;
	}
	*pp = p;

	return x;
}

static int decode_ecm(B_CAS_CARD_PRIVATE_DATA *prv, uint8_t *scramble_key, const ECM_TABLE *in)
{
	int i;
	uint64_t work_key = 0;

	for (i=0;i<KEY_MAX;i++){
		if(prv->table[i] == NULL) {
			break;
		}
		if (prv->table[i]->broadcast_group_id == in->broadcast_group_id &&
		    prv->table[i]->work_key_id == in->work_key_id) {
			work_key = prv->table[i]->work_key;
			break;
		}
	}

	if (work_key == 0) {
		return -1;
	}

	bcas_decrypt(scramble_key, in->scramble_key, work_key, in->protocol_number);

	return 0;
}
