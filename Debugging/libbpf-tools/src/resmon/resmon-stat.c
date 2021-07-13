// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free(lh_entry_k(e));
	free(lh_entry_v(e));
}

/* Fowler–Noll–Vo hash, variant FNV-1 */
static uint64_t resmon_stat_fnv_1(const void *ptr, size_t len)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	const uint8_t *buf = ptr;

	for (size_t i = 0; i < len; i++) {
		hash = hash * 0x100000001b3ULL;
		hash = hash ^ buf[i];
	}
	return hash;
}

struct resmon_stat_key {};

static struct resmon_stat_key *
resmon_stat_key_copy(const struct resmon_stat_key *key, size_t size)
{
	struct resmon_stat_key *copy;

	copy = malloc(size);
	if (copy == NULL)
		return NULL;

	memcpy(copy, key, size);
	return copy;
}

#define RESMON_STAT_KEY_HASH_FN(name, type)				\
	static unsigned long name(const void *k)			\
	{								\
		return resmon_stat_fnv_1(k, sizeof(type));		\
	}

#define RESMON_STAT_KEY_EQ_FN(name, type)				\
	static int name(const void *k1, const void *k2)			\
	{								\
		return memcmp(k1, k2, sizeof(type)) == 0;		\
	}

struct resmon_stat_ralue_key {
	struct resmon_stat_key base;
	enum mlxsw_reg_ralxx_protocol protocol;
	uint8_t prefix_len;
	uint16_t virtual_router;
	struct resmon_stat_dip dip;
};

static struct resmon_stat_ralue_key
resmon_stat_ralue_key(enum mlxsw_reg_ralxx_protocol protocol,
		      uint8_t prefix_len,
		      uint16_t virtual_router,
		      struct resmon_stat_dip dip)
{
	return (struct resmon_stat_ralue_key) {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ralue_hash, struct resmon_stat_ralue_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ralue_eq, struct resmon_stat_ralue_key);

struct resmon_stat_ptar_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
};

static struct resmon_stat_ptar_key
resmon_stat_ptar_key(struct resmon_stat_tcam_region_info tcam_region_info)
{
	return (struct resmon_stat_ptar_key) {
		.tcam_region_info = tcam_region_info,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptar_hash, struct resmon_stat_ptar_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptar_eq, struct resmon_stat_ptar_key);

struct resmon_stat_ptce3_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks flex2_key_blocks;
	uint8_t delta_mask;
	uint8_t delta_value;
	uint16_t delta_start;
	uint8_t erp_id;
};

static struct resmon_stat_ptce3_key
resmon_stat_ptce3_key(struct resmon_stat_tcam_region_info tcam_region_info,
		      const struct resmon_stat_flex2_key_blocks *key_blocks,
		      uint8_t delta_mask,
		      uint8_t delta_value,
		      uint16_t delta_start,
		      uint8_t erp_id)
{
	return (struct resmon_stat_ptce3_key) {
		.tcam_region_info = tcam_region_info,
		.flex2_key_blocks = *key_blocks,
		.delta_mask = delta_mask,
		.delta_value = delta_value,
		.delta_start = delta_start,
		.erp_id = erp_id,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptce3_hash, struct resmon_stat_ptce3_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptce3_eq, struct resmon_stat_ptce3_key);

struct resmon_stat_kvdl_key {
	struct resmon_stat_key base;
	enum resmon_counter resource;
	uint32_t index;
};

static struct resmon_stat_kvdl_key
resmon_stat_kvdl_key(uint32_t index, enum resmon_counter resource)
{
	return (struct resmon_stat_kvdl_key) {
		.index = index,
		.resource = resource,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_kvdl_hash, struct resmon_stat_kvdl_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_kvdl_eq, struct resmon_stat_kvdl_key);

struct resmon_stat_rauht_key {
	struct resmon_stat_key base;
	enum mlxsw_reg_ralxx_protocol protocol;
	uint16_t rif;
	struct resmon_stat_dip dip;
};

static struct resmon_stat_rauht_key
resmon_stat_rauht_key(enum mlxsw_reg_ralxx_protocol protocol,
		      uint16_t rif,
		      struct resmon_stat_dip dip)
{
	return (struct resmon_stat_rauht_key) {
		.protocol = protocol,
		.rif = rif,
		.dip = dip,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_rauht_hash, struct resmon_stat_rauht_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_rauht_eq, struct resmon_stat_rauht_key);

struct resmon_stat_sfd_key {
	struct resmon_stat_key base;
	uint32_t mac;
	uint16_t fid;
	enum resmon_sfd_param_type param_type;
	uint16_t param;
};

static struct resmon_stat_sfd_key
resmon_stat_sfd_key(uint32_t mac, uint16_t fid,
		    enum resmon_sfd_param_type param_type, uint16_t param)
{
	return (struct resmon_stat_sfd_key) {
		.mac = mac,
		.fid = fid,
		.param_type = param_type,
		.param = param,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_sfd_hash, struct resmon_stat_sfd_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_sfd_eq, struct resmon_stat_sfd_key);

struct resmon_stat_sfd_map_key {
	struct resmon_stat_key base;
	uint32_t mac;
	uint16_t fid;
};

static struct resmon_stat_sfd_map_key
resmon_stat_sfd_map_key(uint32_t mac, uint16_t fid)
{
	return (struct resmon_stat_sfd_map_key) {
		.mac = mac,
		.fid = fid,
	};
}

struct resmon_stat_sfd_map_val {
	enum resmon_sfd_param_type param_type;
	uint16_t param;
};

RESMON_STAT_KEY_HASH_FN(resmon_stat_sfd_map_hash, struct resmon_stat_sfd_map_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_sfd_map_eq, struct resmon_stat_sfd_map_key);

struct resmon_stat {
	struct resmon_stat_counters counters;
	struct lh_table *ralue;
	struct lh_table *ptar;
	struct lh_table *ptce3;
	struct lh_table *kvdl;
	struct lh_table *rauht;
	struct lh_table *sfd; /* (mac,fid,param_type,param)->(kvd_alloc) */
	struct lh_table *sfd_map; /* (mac,fid)->(param_type,param) */
};

static struct resmon_stat_kvd_alloc *
resmon_stat_kvd_alloc_copy(struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_kvd_alloc *copy;

	copy = malloc(sizeof(*copy));
	if (copy == NULL)
		return NULL;

	*copy = kvd_alloc;
	return copy;
}

struct resmon_stat *resmon_stat_create(void)
{
	struct lh_table *sfd_map_tab;
	struct lh_table *ralue_tab;
	struct lh_table *ptce3_tab;
	struct lh_table *ptar_tab;
	struct lh_table *kvdl_tab;
	struct lh_table *rauht_tab;
	struct resmon_stat *stat;
	struct lh_table *sfd_tab;

	stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	ralue_tab = lh_table_new(1, resmon_stat_entry_free,
				 resmon_stat_ralue_hash,
				 resmon_stat_ralue_eq);
	if (ralue_tab == NULL)
		goto free_stat;

	ptar_tab = lh_table_new(1, resmon_stat_entry_free,
				resmon_stat_ptar_hash,
				resmon_stat_ptar_eq);
	if (ptar_tab == NULL)
		goto free_ralue_tab;

	ptce3_tab = lh_table_new(1, resmon_stat_entry_free,
				 resmon_stat_ptce3_hash,
				 resmon_stat_ptce3_eq);
	if (ptce3_tab == NULL)
		goto free_ptar_tab;

	kvdl_tab = lh_table_new(1, resmon_stat_entry_free,
				resmon_stat_kvdl_hash,
				resmon_stat_kvdl_eq);
	if (kvdl_tab == NULL)
		goto free_ptce3_tab;

	rauht_tab = lh_table_new(1, resmon_stat_entry_free,
				 resmon_stat_rauht_hash,
				 resmon_stat_rauht_eq);
	if (rauht_tab == NULL)
		goto free_kvdl_tab;

	sfd_tab = lh_table_new(1, resmon_stat_entry_free,
			       resmon_stat_sfd_hash,
			       resmon_stat_sfd_eq);
	if (sfd_tab == NULL)
		goto free_rauht_tab;

	sfd_map_tab = lh_table_new(1, resmon_stat_entry_free,
				   resmon_stat_sfd_map_hash,
				   resmon_stat_sfd_map_eq);
	if (sfd_map_tab == NULL)
		goto free_sfd_tab;

	*stat = (struct resmon_stat){
		.ralue = ralue_tab,
		.ptar = ptar_tab,
		.ptce3 = ptce3_tab,
		.kvdl = kvdl_tab,
		.rauht = rauht_tab,
		.sfd = sfd_tab,
		.sfd_map = sfd_map_tab,
	};
	return stat;

free_sfd_tab:
	lh_table_free(sfd_tab);
free_rauht_tab:
	lh_table_free(rauht_tab);
free_kvdl_tab:
	lh_table_free(kvdl_tab);
free_ptce3_tab:
	lh_table_free(ptce3_tab);
free_ptar_tab:
	lh_table_free(ptar_tab);
free_ralue_tab:
	lh_table_free(ralue_tab);
free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	lh_table_free(stat->sfd_map);
	lh_table_free(stat->sfd);
	lh_table_free(stat->rauht);
	lh_table_free(stat->kvdl);
	lh_table_free(stat->ptce3);
	lh_table_free(stat->ptar);
	lh_table_free(stat->ralue);
	free(stat);
}

struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat)
{
	struct resmon_stat_counters counters = stat->counters;

	for (size_t i = 0; i < resmon_counter_count; i++)
		counters.total += counters.values[i];

	return counters;
}

static void resmon_stat_counter_inc(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] += kvd_alloc.slots;
}

static void resmon_stat_counter_dec(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] -= kvd_alloc.slots;
}

static int resmon_stat_lh_get(struct lh_table *tab,
			      const struct resmon_stat_key *orig_key,
			      struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	const struct resmon_stat_kvd_alloc *kvd_alloc;
	struct lh_entry *e;
	long hash;

	hash = tab->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	kvd_alloc = e->v;
	*ret_kvd_alloc = *kvd_alloc;
	return 0;
}

static struct lh_entry *
resmon_stat_lh_lookup_entry(struct lh_table *tab,
			    const struct resmon_stat_key *orig_key, long hash)
{
	return lh_table_lookup_entry_w_hash(tab, orig_key, hash);
}

static int resmon_stat_lh_insert(struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvd_alloc,
				 long hash)
{
	struct resmon_stat_kvd_alloc *kvd_alloc;
	struct resmon_stat_key *key;
	int rc;

	key = resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	kvd_alloc = resmon_stat_kvd_alloc_copy(orig_kvd_alloc);
	if (kvd_alloc == NULL)
		goto free_key;

	rc = lh_table_insert_w_hash(tab, key, kvd_alloc, hash, 0);
	if (rc)
		goto free_kvd_alloc;

	return 0;

free_kvd_alloc:
	free(kvd_alloc);
free_key:
	free(key);
	return -1;
}

static int
resmon_stat_lh_update_nostats(struct resmon_stat *stat,
			      struct lh_table *tab,
			      const struct resmon_stat_key *orig_key,
			      size_t orig_key_size,
			      struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	struct lh_entry *e;
	long hash = tab->hash_fn(orig_key);

	e = resmon_stat_lh_lookup_entry(tab, orig_key, hash);
	if (e != NULL)
		return 1;

	return resmon_stat_lh_insert(tab, orig_key, orig_key_size,
				     orig_kvd_alloc, hash);
}

static int resmon_stat_lh_update(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	int err;

	err = resmon_stat_lh_update_nostats(stat, tab, orig_key, orig_key_size,
					    orig_kvd_alloc);
	if (err == 1)
		return 0;
	if (err != 0)
		return err;

	resmon_stat_counter_inc(stat, orig_kvd_alloc);
	return 0;
}

static int resmon_stat_lh_delete_nostats(struct resmon_stat *stat,
					 struct lh_table *tab,
					 const struct resmon_stat_key *orig_key,
					 struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct resmon_stat_kvd_alloc *vp;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	vp = e->v;
	*kvd_alloc = *vp;
	rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);
	return 0;
}

static int resmon_stat_lh_delete(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key)
{
	struct resmon_stat_kvd_alloc kvd_alloc;
	int err;

	err = resmon_stat_lh_delete_nostats(stat, tab, orig_key, &kvd_alloc);
	if (err != 0)
		return err;

	resmon_stat_counter_dec(stat, kvd_alloc);
	return 0;
}

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);

	return resmon_stat_lh_update(stat, stat->ralue,
				     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);

	return resmon_stat_lh_delete(stat, stat->ralue, &key.base);
}

int resmon_stat_ptar_alloc(struct resmon_stat *stat,
			   struct resmon_stat_tcam_region_info tcam_region_info,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);

	return resmon_stat_lh_update_nostats(stat, stat->ptar,
					     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ptar_free(struct resmon_stat *stat,
			  struct resmon_stat_tcam_region_info tcam_region_info)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);
	struct resmon_stat_kvd_alloc kvd_alloc;

	return resmon_stat_lh_delete_nostats(stat, stat->ptar, &key.base,
					     &kvd_alloc);
}

int resmon_stat_ptar_get(struct resmon_stat *stat,
			 struct resmon_stat_tcam_region_info tcam_region_info,
			 struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);

	return resmon_stat_lh_get(stat->ptar, &key.base, ret_kvd_alloc);
}

int
resmon_stat_ptce3_alloc(struct resmon_stat *stat,
			struct resmon_stat_tcam_region_info tcam_region_info,
			const struct resmon_stat_flex2_key_blocks *key_blocks,
			uint8_t delta_mask,
			uint8_t delta_value,
			uint16_t delta_start,
			uint8_t erp_id,
			struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);

	return resmon_stat_lh_update(stat, stat->ptce3,
				     &key.base, sizeof(key), kvd_alloc);
}

int
resmon_stat_ptce3_free(struct resmon_stat *stat,
		       struct resmon_stat_tcam_region_info tcam_region_info,
		       const struct resmon_stat_flex2_key_blocks *key_blocks,
		       uint8_t delta_mask,
		       uint8_t delta_value,
		       uint16_t delta_start,
		       uint8_t erp_id)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);

	return resmon_stat_lh_delete(stat, stat->ptce3, &key.base);
}

int resmon_stat_rauht_update(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint16_t rif,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_rauht_key key =
		resmon_stat_rauht_key(protocol, rif, dip);

	return resmon_stat_lh_update(stat, stat->rauht,
				     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_rauht_delete(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint16_t rif,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_rauht_key key =
		resmon_stat_rauht_key(protocol, rif, dip);

	return resmon_stat_lh_delete(stat, stat->rauht, &key.base);
}

static int resmon_stat_kvdl_alloc_1(struct resmon_stat *stat,
				    uint32_t index,
				    enum resmon_counter resource)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index, resource);
	struct resmon_stat_kvd_alloc kvd_alloc = {
		.slots = 1,
		.counter = resource,
	};

	return resmon_stat_lh_update(stat, stat->kvdl,
				     &key.base, sizeof(key), kvd_alloc);
}

static int resmon_stat_kvdl_free_1(struct resmon_stat *stat,
				   uint32_t index,
				   enum resmon_counter resource)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index, resource);

	return resmon_stat_lh_delete(stat, stat->kvdl, &key.base);
}

int resmon_stat_kvdl_alloc(struct resmon_stat *stat,
			   uint32_t index,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	uint32_t i;
	int rc;

	for (i = 0; i < kvd_alloc.slots; i++) {
		rc = resmon_stat_kvdl_alloc_1(stat, index + i,
					      kvd_alloc.counter);
		if (rc != 0)
			goto unroll;
	}

	return 0;

unroll:
	while (i-- > 0)
		resmon_stat_kvdl_free_1(stat, index + i, kvd_alloc.counter);
	return rc;
}

int resmon_stat_kvdl_free(struct resmon_stat *stat,
			  uint32_t index,
			  struct resmon_stat_kvd_alloc kvd_alloc)
{
	int rc = 0;
	int rc_1;

	for (uint32_t i = 0; i < kvd_alloc.slots; i++) {
		rc_1 = resmon_stat_kvdl_free_1(stat, index + i,
					       kvd_alloc.counter);
		if (rc_1 != 0)
			rc = rc_1;
	}

	return rc;
}

static int
resmon_stat_lh_sfd_map_insert(struct resmon_stat *stat,
			      struct resmon_stat_key *orig_key,
			      size_t orig_key_size,
			      enum resmon_sfd_param_type param_type,
			      uint16_t param)
{
	struct lh_table *tab = stat->sfd_map;
	struct resmon_stat_sfd_map_val *val;
	struct resmon_stat_key *key;
	long hash;
	int rc;

	key = resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	val = malloc(sizeof(*val));
	if (val == NULL)
		goto free_key;

	val->param_type= param_type;
	val->param = param;

	hash = tab->hash_fn(orig_key);
	rc = lh_table_insert_w_hash(tab, key, val, hash, 0);
	if (rc)
		goto free_val;

	return 0;

free_val:
	free(val);
free_key:
	free(key);
	return -1;
}

static int
resmon_stat_lh_sfd_map_delete(struct resmon_stat *stat,
			      struct resmon_stat_key *orig_key,
			      enum resmon_sfd_param_type *param_type,
			      uint16_t *param)
{
	const struct resmon_stat_sfd_map_val *vp;
	struct lh_table *tab = stat->sfd_map;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	vp = e->v;
	*param_type = vp->param_type;
	*param = vp->param;

	rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);
	return 0;
}

static int
resmon_stat_sfd_insert(struct resmon_stat *stat,
		       struct resmon_stat_key *orig_sfd_map_key,
		       size_t orig_sfd_map_key_size,
		       struct resmon_stat_key *orig_sfd_key,
		       size_t orig_sfd_key_size,
		       enum resmon_sfd_param_type param_type, uint16_t param,
		       struct resmon_stat_kvd_alloc kvd_alloc)
{
	long hash;
	int err;

	err = resmon_stat_lh_sfd_map_insert(stat, orig_sfd_map_key,
					    orig_sfd_map_key_size, param_type,
					    param);
	if (err)
		return err;

	hash = stat->sfd->hash_fn(orig_sfd_key);
	err = resmon_stat_lh_insert(stat->sfd, orig_sfd_key,
				    orig_sfd_key_size, kvd_alloc, hash);
	if (err)
		goto sfd_map_remove;

	return 0;

sfd_map_remove:
	resmon_stat_lh_sfd_map_delete(stat, orig_sfd_map_key, &param_type,
				      &param);
	return err;
}

static int
resmon_stat_sfd_delete_nostats(struct resmon_stat *stat,
			       struct resmon_stat_key *sfd_map_key_base,
			       struct resmon_stat_key *sfd_key_base)
{
	enum resmon_sfd_param_type old_param_type;
	struct resmon_stat_kvd_alloc kvd_alloc;
	uint16_t old_param;
	int err;

	err = resmon_stat_lh_sfd_map_delete(stat, sfd_map_key_base,
					    &old_param_type, &old_param);
	if (err)
		return err;

	return resmon_stat_lh_delete_nostats(stat, stat->sfd, sfd_key_base,
					     &kvd_alloc);
}

int
resmon_stat_sfd_update(struct resmon_stat *stat, uint32_t mac, uint16_t fid,
		       enum resmon_sfd_param_type param_type,
		       uint16_t param,
		       struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	struct resmon_stat_key *sfd_map_key_base, *sfd_key_base;
	struct resmon_stat_sfd_map_key sfd_map_key;
	struct resmon_stat_sfd_key sfd_key;
	bool new_entry = true;
	struct lh_entry *e;
	long hash;
	int err;

	sfd_map_key = resmon_stat_sfd_map_key(mac, fid);
	sfd_map_key_base = &sfd_map_key.base;
	sfd_key = resmon_stat_sfd_key(mac, fid, param_type, param);
	sfd_key_base = &sfd_key.base;


	hash = stat->sfd_map->hash_fn(sfd_map_key_base);
	e = resmon_stat_lh_lookup_entry(stat->sfd_map, sfd_map_key_base, hash);
	if (e != NULL) {
		err = resmon_stat_sfd_delete_nostats(stat, sfd_map_key_base,
						     sfd_key_base);
		if (err)
			return err;

		new_entry = false;
	}

	err = resmon_stat_sfd_insert(stat, sfd_map_key_base,
				     sizeof(sfd_map_key), sfd_key_base,
				     sizeof(sfd_key), param_type, param,
				     orig_kvd_alloc);
	if (err)
		return err;

	if (new_entry)
		resmon_stat_counter_inc(stat, orig_kvd_alloc);

	return 0;
}

int
resmon_stat_sfd_delete(struct resmon_stat *stat, uint32_t mac, uint16_t fid)
{
	struct resmon_stat_sfd_map_key sfd_map_key;
	enum resmon_sfd_param_type param_type;
	struct resmon_stat_sfd_key sfd_key;
	uint16_t param;
	int err;

	sfd_map_key = resmon_stat_sfd_map_key(mac, fid);

	err = resmon_stat_lh_sfd_map_delete(stat, &sfd_map_key.base,
					    &param_type, &param);
	if (err)
		return err;

	sfd_key = resmon_stat_sfd_key(mac, fid, param_type, param);
	return resmon_stat_lh_delete(stat, stat->sfd, &sfd_key.base);
}

static bool resmon_stat_sfd_keys_equal(const struct resmon_stat_sfd_key *key1,
				       const struct resmon_stat_sfd_key *key2,
				       uint8_t flags)
{
	if ((flags & RESMON_STAT_SFD_KEY_MAC) && key1->mac != key2->mac)
		return false;

	if ((flags & RESMON_STAT_SFD_KEY_FID) && key1->fid != key2->fid)
		return false;

	if ((flags & RESMON_STAT_SFD_KEY_PARAM_TYPE) && \
			key1->param_type != key2->param_type)
		return false;

	if ((flags & RESMON_STAT_SFD_KEY_PARAM) && key1->param != key2->param)
		return false;

	return true;
}

int resmon_stat_sfdf_flush(struct resmon_stat *stat, uint16_t fid,
			   enum resmon_sfd_param_type param_type,
			   uint16_t param, uint8_t flags)
{
	struct resmon_stat_sfd_map_key sfd_map_key;
	enum resmon_sfd_param_type old_param_type;
	struct resmon_stat_sfd_key expected_key;
	const struct resmon_stat_sfd_key *key;
	struct lh_entry *e, *tmp;
	uint16_t old_param;
	int err;

	expected_key = resmon_stat_sfd_key(0, fid, param_type, param);

	lh_foreach_safe(stat->sfd, e, tmp) {
		key = e->k;

		if (resmon_stat_sfd_keys_equal(&expected_key, key, flags)) {
			sfd_map_key = resmon_stat_sfd_map_key(key->mac, key->fid);
			err = resmon_stat_lh_sfd_map_delete(stat,
							    &sfd_map_key.base,
							    &old_param_type, &old_param);
			if (err)
				return err;

			err = resmon_stat_lh_delete(stat, stat->sfd, &key->base);
			if (err)
				return err;
		}
	}

	return 0;
}
