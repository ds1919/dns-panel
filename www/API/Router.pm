package API::Router;

use strict;
use warnings;
use utf8;

use FindBin; use lib "$FindBin::RealBin/include";
use JSON qw(decode_json);
use API::Response;
use functions qw(zone_delete_everywhere 
    pdns_list_domains pdns_get_domain pdns_get_domain_by_name pdns_find_domain_by_name
    pdns_count_records_by_type pdns_list_subnames pdns_list_child_zones
    pdns_search_records dns_name_ascii dns_name_unicode pdns_names_with_address ptr_suffix_for_partial_ip dns_query dns_check_propagation
    pdns_list_rrsets pdns_apply_rrsets
    pdns_create_zone zone_activate_after_create pdns_delete_zone pdns_zone_defaults pdns_zone_snapshot dns_validate_zonename
    pdns_soa_fields pdns_update_soa pdns_apex_ns_list pdns_apex_ns_mutate pdns_record_mutate pdns_records_batch
    reverse_master_for_ip reverse_candidates_for_ip pdns_create_address_ptr zone_ptr_statuses dns_validate effective_zone_access
    ptr_reverse_for_record pdns_create_record_ptr pdns_delete_records_ptr is_ip_addr
    zone_profile_names zone_profiles_for_form zone_profile_preset get_config_value zone_role_norm
    zone_profiles_all zone_profile_get zone_profile_create zone_profile_update zone_profile_delete
    reverse_zones_for_cidr reverse_plan_for_cidr pdns_create_zones_batch
    zone_activate zone_verify zone_deactivate zone_sync_verify set_zone_sync_state dns_agent_call
    get_zone_sync_state sync_problem_zones retry_zone_activation zone_secondary_refresh
    zone_dynamic_get zone_dynamic_save dyn_profiles_all dyn_profile_save dyn_profile_delete tsig_keys_all
    import_probe_queue import_zone_diff import_zone_take import_zone_copy_ops
    label_categories_all zone_labels_get zone_labels_map zone_labels_set zone_labels_delete_all
    zone_distribution_cleanup
    label_category_create label_category_delete label_value_create label_value_delete
    pulse_testers_all pulse_tester_save pulse_tester_delete pulse_enroll_key_new pulse_server_address_set
    pulse_groups_all pulse_group_save pulse_group_delete pulse_group_members_set
    pulse_checks_all pulse_check_save pulse_check_delete pulse_check_groups_set pulse_history
    pulse_rrset_history
    pulse_zones_writable pulse_rule_candidates pulse_rrset_draft
    pulse_rules_all pulse_rule_get pulse_rule_create pulse_rule_update pulse_rule_delete pulse_rule_clone_to
    pulse_rule_branches_set pulse_server_hint
    effective_zone_access build_access_context access_for pdns_profile_map zone_kind
    pdns_set_zone_metas pdns_get_domain_metadata
    has_capability capability_check audit_log audit_target_label audit_history audit_search audit_filter_options get_client_ip node_health
    ha_manager_request ha_mode ha_enabled ha_pair_address ha_pair_address_set
    tsig_keys_all tsig_key_meta tsig_key_create tsig_keys_forget_unused tsig_key_forget_unused_by_name tsig_key_secret
    ip_groups_all ip_group_get ip_group_create ip_group_update ip_group_delete secondary_group_prefixes_set
    ip_group_member_add ip_group_member_delete
    pdns_endpoints
    secondary_groups_all secondary_group_get secondary_group_create secondary_group_update secondary_group_delete
    secondary_group_member_add secondary_group_member_remove
    secondary_group_ip_group_add secondary_group_ip_group_remove
    secondary_group_tsig_key_add secondary_group_tsig_key_remove secondary_group_tsig_set_primary secondary_group_tsig_key_create_and_add
    secondary_nodes_all secondary_node_get secondary_node_create secondary_node_update secondary_node_delete
    secondary_server_save secondary_server_get secondary_servers_list secondary_server_delete
    secondary_node_endpoint_add secondary_node_endpoint_update secondary_node_endpoint_delete secondary_node_endpoint_get
    catalogs_all catalog_get catalog_create catalog_update catalog_delete
    catalog_groups_get catalog_groups_set catalog_nodes_get catalog_node_remove node_catalogs_set nodes_catalogs_map
    catalog_zones zone_catalog_of zone_catalog_map catalogs_available catalog_provision
    catalog_subscription_config catalog_subscription_recheck catalog_consumers_state
    zone_direct_axfr_map zone_direct_axfr_set direct_axfr_zones
    zone_recipients zone_catalog_set zone_policy_materialize policy_refresh zones_direct_axfr_set
    zone_promote_to_primary zone_demote_to_secondary zone_secondary_source_set
    upstream_tsig_resolve upstream_tsig_rollback upstream_tsig_keys import_update_from
    zone_dnssec_get zone_dnssec_set zone_dnssec_key_add zone_dnssec_key_set zone_dnssec_key_delete
    secondary_node_tsig_key_add secondary_node_tsig_key_remove secondary_node_tsig_set_primary
    secondary_node_tsig_key_create_and_add secondary_node_set_default_group
    users_all user_get user_create user_update user_delete
    perm_groups_all perm_group_get perm_group_create perm_group_update perm_group_delete
    user_group_add user_group_remove capability_grant capability_revoke
    zone_access_set zone_access_delete auth_identity_add auth_identity_delete
    set_user_password auth_totp_disable auth_totp_reset auth_totp_require user_sessions zone_access_effective user_access_set user_access_preview group_access_set
    session_ttl_default user_session_ttl user_session_ttl_raw set_user_session_ttl session_revoke session_revoke_all session_by_raw
    account_overview account_password_change account_totp_begin account_totp_confirm account_totp_cancel account_totp_disable
    account_recovery_regenerate account_prefs_set account_themes setting
                 pulse_sweep_rrset_history
                 pulse_policy_set pulse_policy_fields
                 pulse_check_defaults
                 bind_export_zones bind_export_sources zone_import_apply
                 import_source_load import_sources_all import_source_get import_inventory import_zone_mark
                 import_zone_dnssec import_zone_dnssec_keys import_zone_dnssec_unsigned
                 external_settings external_settings_set api_token_list api_token_create api_token_update
                 api_token_delete api_token_get
                 oidc_provider_list oidc_provider_create oidc_provider_update oidc_provider_delete oidc_provider_get);
use API::OpenAPI ();

# Minimal API router: METHOD + PATH_INFO dispatched through @ROUTES.

sub new {
    my ($class, $cgi, $user) = @_;
    return bless { cgi => $cgi, user => $user }, $class;
}

my @ROUTES = (
    [ 'GET',  qr{^/health$},                  \&_health ],
    [ 'GET',  qr{^/health/live$},             \&_health_live ],
    [ 'GET',  qr{^/health/ready$},            \&_health_ready ],
    [ 'GET',  qr{^/openapi\.json$},            \&_openapi ],
    # External access: remote MCP, anonymous read, OIDC and API tokens (users.manage).
    [ 'GET',    qr{^/external$},                \&_external_get ],
    [ 'PUT',    qr{^/external$},                \&_external_set ],
    [ 'POST',   qr{^/external/tokens$},         \&_token_create ],
    [ 'PATCH',  qr{^/external/tokens/(\d+)$},   \&_token_update ],
    [ 'DELETE', qr{^/external/tokens/(\d+)$},   \&_token_delete ],
    [ 'POST',   qr{^/external/oidc$},           \&_oidc_create ],
    [ 'PATCH',  qr{^/external/oidc/(\d+)$},     \&_oidc_update ],
    [ 'DELETE', qr{^/external/oidc/(\d+)$},     \&_oidc_delete ],
    # HA: a thin wrapper over the manager's control socket. The panel holds no HA logic: it reads state and
    # submits intents; the manager decides and executes.
    [ 'GET',  qr{^/ha/status$},                    \&_ha_status ],
    [ 'GET',  qr{^/ha/config$},                    \&_ha_config_get ],
    [ 'PUT',  qr{^/ha/config$},                    \&_ha_config_put ],
    [ 'PUT',  qr{^/ha/publication$},               \&_ha_publication_put ],
    [ 'PUT',  qr{^/ha/pair-address$},              \&_ha_pair_address_put ],
    [ 'GET',  qr{^/ha/operations$},                \&_ha_operations ],
    [ 'GET',  qr{^/ha/operations/([\w.\-]+)$},     \&_ha_operation ],
    [ 'POST', qr{^/ha/switchover$},                \&_ha_switchover ],
    [ 'POST', qr{^/ha/emergency$},                 \&_ha_emergency ],
    [ 'POST', qr{^/ha/reseed$},                    \&_ha_reseed ],
    [ 'POST', qr{^/ha/dismantle$},                 \&_ha_dismantle ],
    [ 'POST', qr{^/ha/operations/([\w.\-]+)/resume$}, \&_ha_resume ],
    # Pairing and pair creation: a separate branch because it must work BEFORE a pair exists.
    [ 'GET',  qr{^/ha/pair$},                      \&_ha_pair_status ],
    [ 'GET',  qr{^/ha/pair/inventory$},            \&_ha_pair_inventory ],
    [ 'GET',  qr{^/ha/pair/devices$},              \&_ha_pair_devices ],
    [ 'POST', qr{^/ha/pair/create$},               \&_ha_pair_create ],
    [ 'POST', qr{^/ha/pair/join$},                 \&_ha_pair_join ],
    [ 'POST', qr{^/ha/pair/approve$},              \&_ha_pair_approve ],
    [ 'POST', qr{^/ha/pair/reject$},               \&_ha_pair_reject ],
    [ 'POST', qr{^/ha/pair/reset$},                \&_ha_pair_reset ],
    [ 'POST', qr{^/ha/pair/build$},                \&_ha_pair_build ],
    [ 'GET',    qr{^/zones$},                   \&_list_zones ],
    [ 'POST',   qr{^/zones$},                   \&_create_zone ],
    [ 'POST',   qr{^/zones/import/sources$},     \&_zone_import_sources ],
    [ 'GET',    qr{^/import/sources$},            \&_import_sources_list ],
    [ 'POST',   qr{^/import/sources$},            \&_import_source_load ],
    [ 'GET',    qr{^/import/zones/(\d+)/dnssec$},      \&_import_zone_dnssec ],
    [ 'PUT',    qr{^/import/zones/(\d+)/dnssec$},      \&_import_zone_dnssec_unsigned ],
    [ 'POST',   qr{^/import/zones/(\d+)/dnssec/keys$}, \&_import_zone_dnssec_keys ],
    [ 'GET',    qr{^/import/sources/(\d+)$},      \&_import_inventory ],
    [ 'POST',   qr{^/import/zones/(\d+)/mark$},   \&_import_zone_mark ],
    [ 'POST',   qr{^/zones/import$},             \&_zone_import_apply ],
    [ 'GET',    qr{^/audit$},                   \&_audit_list ],
    [ 'GET',    qr{^/zones/defaults$},          \&_zone_defaults ],
    [ 'GET',    qr{^/zone-profiles$},           \&_zp_list ],
    [ 'POST',   qr{^/zone-profiles$},           \&_zp_create ],
    [ 'GET',    qr{^/zone-profiles/(\d+)$},     \&_zp_get ],
    [ 'PUT',    qr{^/zone-profiles/(\d+)$},     \&_zp_update ],
    [ 'DELETE', qr{^/zone-profiles/(\d+)$},     \&_zp_delete ],
    [ 'GET',    qr{^/reverse/preview$},         \&_reverse_preview ],
    [ 'POST',   qr{^/reverse$},                  \&_create_reverse ],
    [ 'DELETE', qr{^/zones/(\d+)$},             \&_delete_zone ],
    [ 'PATCH',  qr{^/zones/(\d+)$},             \&_patch_zone ],
    [ 'GET',  qr{^/zones/(\d+)$},             \&_get_zone ],
    [ 'GET',  qr{^/zones/(\d+)/stats$},       \&_zone_stats ],
    [ 'GET',  qr{^/zones/(\d+)/subdomains$},  \&_zone_subdomains ],
    [ 'GET',    qr{^/zones/(\d+)/propagation$}, \&_zone_propagation ],
    [ 'GET',    qr{^/zones/(\d+)/ptr-status$},  \&_zone_ptr_status ],
    [ 'GET',    qr{^/sync/problems$},            \&_sync_problems ],
    [ 'POST',   qr{^/zones/(\d+)/retry-sync$},   \&_retry_sync ],
    [ 'POST',   qr{^/zones/(\d+)/refresh-axfr$}, \&_refresh_axfr ],
    [ 'GET',    qr{^/zones/(\d+)/dynamic$},     \&_zone_dynamic_get ],
    [ 'PUT',    qr{^/zones/(\d+)/dynamic$},     \&_zone_dynamic ],
    [ 'GET',    qr{^/zones/(\d+)/dnssec$},      \&_zone_dnssec_get ],
    [ 'PUT',    qr{^/zones/(\d+)/dnssec$},      \&_zone_dnssec_set ],
    [ 'POST',   qr{^/zones/(\d+)/dnssec/keys$}, \&_zone_dnssec_key_add ],
    [ 'PUT',    qr{^/zones/(\d+)/dnssec/keys/(\d+)$}, \&_zone_dnssec_key_set ],
    [ 'DELETE', qr{^/zones/(\d+)/dnssec/keys/(\d+)$}, \&_zone_dnssec_key_delete ],
    [ 'GET',    qr{^/dynamic/profiles$},          \&_dynp_list ],
    [ 'POST',   qr{^/import/sources/(\d+)/probe$}, \&_import_probe ],
    [ 'GET',    qr{^/import/zones/(\d+)/diff$},    \&_import_diff ],
    [ 'POST',   qr{^/import/zones/(\d+)/take$},    \&_import_take ],
    [ 'POST',   qr{^/import/zones/(\d+)/copy$},    \&_import_copy ],
    [ 'POST',   qr{^/dynamic/profiles$},          \&_dynp_create ],
    [ 'PUT',    qr{^/dynamic/profiles/(\d+)$},   \&_dynp_update ],
    [ 'DELETE', qr{^/dynamic/profiles/(\d+)$},   \&_dynp_delete ],
    [ 'POST',   qr{^/zones/(\d+)/promote$},      \&_zone_promote ],
    [ 'POST',   qr{^/zones/(\d+)/demote$},       \&_zone_demote  ],
    [ 'PUT',    qr{^/zones/(\d+)/secondary-source$}, \&_zone_secondary_source ],
    [ 'GET',    qr{^/zones/upstream-keys$},     \&_zone_upstream_keys ],
    [ 'GET',    qr{^/records/search$},          \&_search_records ],
    [ 'GET',    qr{^/dns/query$},               \&_dns_query ],
    [ 'GET',    qr{^/labels$},                   \&_list_labels ],
    [ 'POST',   qr{^/labels/categories$},        \&_create_label_category ],
    [ 'DELETE', qr{^/labels/categories/(\d+)$},  \&_delete_label_category ],
    [ 'POST',   qr{^/labels/values$},            \&_create_label_value ],
    [ 'DELETE', qr{^/labels/values/(\d+)$},      \&_delete_label_value ],
    # RRset contract: the unit is name+type.
    [ 'GET',    qr{^/zones/(\d+)/rrsets$},       \&_list_rrsets ],
    [ 'PATCH',  qr{^/zones/(\d+)/rrsets$},       \&_patch_rrsets ],
    [ 'PATCH',  qr{^/zones/(\d+)/soa$},          \&_patch_soa ],
    [ 'GET',    qr{^/zones/(\d+)/audit$},        \&_zone_audit ],
    [ 'POST',   qr{^/zones/(\d+)/name-servers$},         \&_ns_add ],
    [ 'PATCH',  qr{^/zones/(\d+)/name-servers/(\d+)$},   \&_ns_update ],
    [ 'DELETE', qr{^/zones/(\d+)/name-servers/(\d+)$},   \&_ns_delete ],
    [ 'POST',   qr{^/zones/(\d+)/records/batch$},        \&_records_batch ],
    [ 'POST',   qr{^/zones/(\d+)/records/delete$},       \&_records_delete ],
    [ 'POST',   qr{^/zones/(\d+)/records/with-ptr$},     \&_record_add_with_ptr ],
    [ 'POST',   qr{^/zones/(\d+)/records/(\d+)/ptr$},    \&_record_create_ptr ],
    [ 'POST',   qr{^/zones/(\d+)/records$},              \&_record_add ],
    [ 'PATCH',  qr{^/zones/(\d+)/records/(\d+)$},        \&_record_update ],
    [ 'DELETE', qr{^/zones/(\d+)/records/(\d+)$},        \&_record_delete ],
    [ 'PUT',    qr{^/zones/(\d+)/labels$},       \&_put_zone_labels ],
    # Secondary distribution inventory (docs/21 §9).
    # Permissions: TSIG/IP groups/bindings and PowerDNS addresses -> distribution.manage; nodes/groups/endpoints -> secondary.manage.
    # TSIG keys (distribution.manage)
    [ 'GET',    qr{^/secondary/tsig-keys/(\d+)/secret$},          \&_tsig_reveal ],
    # IP groups (distribution.manage)
    [ 'GET',    qr{^/secondary/ip-groups$},                       \&_ipg_list ],
    [ 'POST',   qr{^/secondary/ip-groups$},                       \&_ipg_create ],
    [ 'DELETE', qr{^/secondary/ip-groups/(\d+)/members/(\d+)$},   \&_ipg_member_del ],
    [ 'POST',   qr{^/secondary/ip-groups/(\d+)/members$},         \&_ipg_member_add ],
    [ 'GET',    qr{^/secondary/ip-groups/(\d+)$},                 \&_ipg_get ],
    [ 'PATCH',  qr{^/secondary/ip-groups/(\d+)$},                 \&_ipg_update ],
    [ 'DELETE', qr{^/secondary/ip-groups/(\d+)$},                 \&_ipg_delete ],
    # Our PowerDNS addresses are ONE list per installation; see functions.pm, "Our PowerDNS addresses".
    # Secondary groups (secondary.manage) + bindings (distribution.manage)
    [ 'GET',    qr{^/secondary/groups$},                          \&_sg_list ],
    [ 'POST',   qr{^/secondary/groups$},                          \&_sg_create ],
    [ 'DELETE', qr{^/secondary/groups/(\d+)/members/(\d+)$},      \&_sg_member_del ],
    [ 'POST',   qr{^/secondary/groups/(\d+)/members$},            \&_sg_member_add ],
    [ 'DELETE', qr{^/secondary/groups/(\d+)/ip-groups/(\d+)$},    \&_sg_ipg_del ],
    [ 'POST',   qr{^/secondary/groups/(\d+)/ip-groups$},          \&_sg_ipg_add ],
    [ 'POST',   qr{^/secondary/groups/(\d+)/tsig-keys/(\d+)/primary$}, \&_sg_tsig_primary ],
    [ 'DELETE', qr{^/secondary/groups/(\d+)/tsig-keys/(\d+)$},    \&_sg_tsig_del ],
    [ 'POST',   qr{^/secondary/groups/(\d+)/tsig-keys$},          \&_sg_tsig_add ],
    [ 'GET',    qr{^/secondary/groups/(\d+)$},                    \&_sg_get ],
    [ 'PATCH',  qr{^/secondary/groups/(\d+)$},                    \&_sg_update ],
    [ 'DELETE', qr{^/secondary/groups/(\d+)$},                    \&_sg_delete ],
    # Secondary nodes (secondary.manage)
    [ 'GET',    qr{^/secondary/servers$},                         \&_srv_list ],
    [ 'POST',   qr{^/secondary/servers$},                         \&_srv_create ],
    [ 'GET',    qr{^/secondary/servers/(\d+)/audit$},             \&_srv_audit ],
    [ 'GET',    qr{^/secondary/servers/(\d+)$},                   \&_srv_get ],
    [ 'PUT',    qr{^/secondary/servers/(\d+)$},                   \&_srv_update ],
    [ 'PUT',    qr{^/secondary/servers/(\d+)/catalogs$},          \&_srv_catalogs_set ],
    [ 'PUT',    qr{^/secondary/servers/(\d+)/default-group$},     \&_srv_default_group ],
    [ 'POST',   qr{^/secondary/servers/(\d+)/tsig-keys$},         \&_srv_tsig_add ],
    [ 'POST',   qr{^/secondary/servers/(\d+)/tsig-keys/(\d+)/primary$}, \&_srv_tsig_primary ],
    [ 'DELETE', qr{^/secondary/servers/(\d+)/tsig-keys/(\d+)$},   \&_srv_tsig_del ],
    [ 'DELETE', qr{^/secondary/servers/(\d+)$},                   \&_srv_delete ],
    [ 'GET',    qr{^/secondary/nodes$},                           \&_sn_list ],
    [ 'POST',   qr{^/secondary/nodes$},                           \&_sn_create ],
    [ 'DELETE', qr{^/secondary/nodes/(\d+)/endpoints/(\d+)$},     \&_sn_ep_del ],
    [ 'PATCH',  qr{^/secondary/nodes/(\d+)/endpoints/(\d+)$},     \&_sn_ep_update ],
    [ 'POST',   qr{^/secondary/nodes/(\d+)/endpoints$},           \&_sn_ep_add ],
    [ 'GET',    qr{^/secondary/nodes/(\d+)$},                     \&_sn_get ],
    [ 'PATCH',  qr{^/secondary/nodes/(\d+)$},                     \&_sn_update ],
    [ 'DELETE', qr{^/secondary/nodes/(\d+)$},                     \&_sn_delete ],
    # --- NS Pulse — pulse.manage (docs/25-ns-pulse.md) ---
    # Narrow paths before broad ones, or /pulse/rules/1 would swallow /pulse/rules/1/branches.
    [ 'GET',    qr{^/pulse$},                                     \&_pulse_all ],
    [ 'POST',   qr{^/pulse/enrollment/key$},                      \&_pulse_enroll_key_new ],
    [ 'PUT',    qr{^/pulse/server/address$},                      \&_pulse_server_address ],
    [ 'POST',   qr{^/pulse/testers/(\d+)/approve$},                \&_pulse_tester_approve ],
    [ 'PUT',    qr{^/pulse/testers/(\d+)$},                        \&_pulse_tester_update ],
    [ 'DELETE', qr{^/pulse/testers/(\d+)$},                        \&_pulse_tester_delete ],
    [ 'POST',   qr{^/pulse/groups$},                              \&_pulse_group_create ],
    [ 'PUT',    qr{^/pulse/groups/(\d+)/members$},                 \&_pulse_group_members ],
    [ 'PUT',    qr{^/pulse/groups/(\d+)$},                         \&_pulse_group_update ],
    [ 'DELETE', qr{^/pulse/groups/(\d+)$},                         \&_pulse_group_delete ],
    [ 'GET',    qr{^/pulse/history$},                             \&_pulse_history ],
    [ 'GET',    qr{^/pulse/zones/(\d+)/rrset/history$},              \&_pulse_rrset_history ],
    [ 'GET',    qr{^/pulse/zones/(\d+)/rrset/sweep$},                \&_pulse_rrset_sweep ],
    [ 'PUT',    qr{^/pulse/settings$},                            \&_pulse_settings_set ],
    [ 'POST',   qr{^/pulse/checks$},                              \&_pulse_check_create ],
    [ 'PUT',    qr{^/pulse/checks/(\d+)/groups$},                  \&_pulse_check_groups ],
    [ 'PUT',    qr{^/pulse/checks/(\d+)$},                         \&_pulse_check_update ],
    [ 'DELETE', qr{^/pulse/checks/(\d+)$},                         \&_pulse_check_delete ],
    [ 'GET',    qr{^/pulse/zones/(\d+)/records$},                   \&_pulse_zone_records ],
    [ 'GET',    qr{^/pulse/zones/(\d+)/rrset$},                     \&_pulse_rrset ],
    [ 'POST',   qr{^/pulse/rules$},                               \&_pulse_rule_create ],
    [ 'PUT',    qr{^/pulse/rules/(\d+)/branches$},                 \&_pulse_rule_branches ],
    [ 'POST',   qr{^/pulse/rules/(\d+)/clone$},                    \&_pulse_rule_clone ],
    [ 'GET',    qr{^/pulse/rules/(\d+)$},                          \&_pulse_rule_get ],
    [ 'PUT',    qr{^/pulse/rules/(\d+)$},                          \&_pulse_rule_update ],
    [ 'DELETE', qr{^/pulse/rules/(\d+)$},                          \&_pulse_rule_delete ],
    # --- Catalogs and zone distribution (distribution.manage) ---
    [ 'GET',    qr{^/catalogs$},                                  \&_cat_list ],
    [ 'POST',   qr{^/catalogs$},                                  \&_cat_create ],
    [ 'GET',    qr{^/catalogs/(\d+)$},                            \&_cat_get ],
    [ 'PATCH',  qr{^/catalogs/(\d+)$},                            \&_cat_update ],
    [ 'DELETE', qr{^/catalogs/(\d+)$},                            \&_cat_delete ],
    [ 'PUT',    qr{^/catalogs/(\d+)/groups$},                     \&_cat_groups_set ],
    # Re-provisioning the producer zone is its own action, not an "edit with no fields": it has no editable
    # fields, and the edit route rightly rejects a PATCH with an empty body.
    [ 'POST',   qr{^/catalogs/(\d+)/provision$},                  \&_cat_provision ],
    [ 'DELETE', qr{^/catalogs/(\d+)/nodes/(\d+)$},                \&_cat_node_remove ],
    [ 'GET',    qr{^/catalogs/(\d+)/subscriptions/(\d+)/config$},  \&_cat_sub_config ],
    [ 'POST',   qr{^/catalogs/(\d+)/subscriptions/(\d+)/recheck$}, \&_cat_sub_recheck ],
    # Zone distribution is two independent facts, hence two routes. A single "set up delivery" call would
    # inevitably decide for the operator what to do with the other list.
    [ 'GET',    qr{^/zones/(\d+)/distribution$},                  \&_zdist_get ],
    [ 'PUT',    qr{^/zones/(\d+)/direct-axfr$},                   \&_zdirect_set ],
    # Bulk is ONE request, not one per zone: thirteen sequential requests kept the user waiting for seconds.
    [ 'PUT',    qr{^/zones/direct-axfr$},                        \&_zdirect_bulk ],
    [ 'PUT',    qr{^/zones/(\d+)/catalog$},                       \&_zcatalog_set ],

    # --- Account: the caller's own. Needs no admin rights; there is no way to pass someone else's id. ---
    [ 'GET',    qr{^/account$},                                  \&_acct_get ],
    [ 'POST',   qr{^/account/password$},                         \&_acct_password ],
    [ 'POST',   qr{^/account/totp/begin$},                       \&_acct_totp_begin ],
    [ 'POST',   qr{^/account/totp/confirm$},                     \&_acct_totp_confirm ],
    [ 'DELETE', qr{^/account/totp/pending$},                     \&_acct_totp_cancel ],
    [ 'DELETE', qr{^/account/totp$},                             \&_acct_totp_off ],
    [ 'POST',   qr{^/account/recovery-codes$},                   \&_acct_recovery ],
    [ 'PUT',    qr{^/account/preferences$},                      \&_acct_prefs ],
    [ 'DELETE', qr{^/account/sessions/(\d+)$},                   \&_acct_session_revoke ],
    [ 'DELETE', qr{^/account/sessions$},                         \&_acct_sessions_revoke_others ],
    # --- Users & access (Settings -> Users & access). All under users.manage; mutations are audited. ---
    [ 'GET',    qr{^/users$},                                     \&_usr_list ],
    [ 'POST',   qr{^/users$},                                     \&_usr_create ],
    [ 'GET',    qr{^/users/(\d+)$},                               \&_usr_get ],
    [ 'PUT',    qr{^/users/(\d+)$},                               \&_usr_update ],
    [ 'DELETE', qr{^/users/(\d+)$},                               \&_usr_delete ],
    [ 'POST',   qr{^/users/(\d+)/password$},                      \&_usr_password ],
    [ 'POST',   qr{^/users/(\d+)/totp/reset$},                    \&_usr_totp_reset ],
    [ 'PUT',    qr{^/users/(\d+)/totp/required$},                 \&_usr_totp_required ],
    [ 'DELETE', qr{^/users/(\d+)/totp$},                          \&_usr_totp_off ],
    [ 'GET',    qr{^/users/(\d+)/sessions$},                      \&_usr_sessions ],
    [ 'DELETE', qr{^/users/(\d+)/sessions/(\d+)$},                \&_usr_session_revoke ],
    [ 'DELETE', qr{^/users/(\d+)/sessions$},                      \&_usr_session_revoke_all ],
    [ 'PUT',    qr{^/users/(\d+)/session-policy$},                \&_usr_session_policy ],
    [ 'GET',    qr{^/users/(\d+)/effective-access$},              \&_usr_effective ],
    [ 'POST',   qr{^/users/(\d+)/access/preview$},                \&_usr_access_preview ],
    [ 'PUT',    qr{^/users/(\d+)/access$},                        \&_usr_access_set ],
    [ 'POST',   qr{^/users/(\d+)/groups$},                        \&_usr_group_add ],
    [ 'DELETE', qr{^/users/(\d+)/groups/(\d+)$},                  \&_usr_group_del ],
    [ 'POST',   qr{^/users/(\d+)/capabilities$},                  \&_usr_cap_add ],
    [ 'DELETE', qr{^/users/(\d+)/capabilities/([A-Za-z0-9._]+)$}, \&_usr_cap_del ],
    [ 'POST',   qr{^/users/(\d+)/zone-access$},                   \&_usr_za_set ],
    [ 'POST',   qr{^/users/(\d+)/identities$},                    \&_usr_ident_add ],
    [ 'DELETE', qr{^/identities/(\d+)$},                          \&_usr_ident_del ],
    [ 'DELETE', qr{^/zone-access/(\d+)$},                         \&_usr_za_del ],

    [ 'GET',    qr{^/permission-groups$},                         \&_pg_list ],
    [ 'POST',   qr{^/permission-groups$},                         \&_pg_create ],
    [ 'GET',    qr{^/permission-groups/(\d+)$},                   \&_pg_get ],
    [ 'PUT',    qr{^/permission-groups/(\d+)$},                   \&_pg_update ],
    [ 'DELETE', qr{^/permission-groups/(\d+)$},                   \&_pg_delete ],
    [ 'POST',   qr{^/permission-groups/(\d+)/members$},           \&_pg_member_add ],
    [ 'DELETE', qr{^/permission-groups/(\d+)/members/(\d+)$},     \&_pg_member_del ],
    [ 'POST',   qr{^/permission-groups/(\d+)/capabilities$},      \&_pg_cap_add ],
    [ 'DELETE', qr{^/permission-groups/(\d+)/capabilities/([A-Za-z0-9._]+)$}, \&_pg_cap_del ],
    [ 'POST',   qr{^/permission-groups/(\d+)/zone-access$},       \&_pg_za_set ],
    [ 'PUT',    qr{^/permission-groups/(\d+)/access$},            \&_pg_access_set ],
);

sub handle_request {
    my ($self) = @_;
    my $method = $ENV{'REQUEST_METHOD'} || 'GET';
    my $path   = $ENV{'PATH_INFO'} || '/';
    $path =~ s{/+$}{};
    $path = '/' if $path eq '';

    for my $route (@ROUTES) {
        my ($m, $re, $handler) = @$route;
        next unless $m eq $method;
        if (my @caps = ($path =~ $re)) {
            # A match without capture groups yields @caps = (1); normalise it.
            @caps = () if @caps == 1 && $caps[0] eq '1' && $path !~ /\d/;
            return $handler->($self, @caps);
        }
    }

    return API::Response->not_found("No route for $method $path");
}

# --- Handlers ---

# Access context is built ONCE per request (rules are loaded from the DB a single time).
sub _ctx { my ($self) = @_; return $self->{_ctx} //= build_access_context($self->{user}); }

# Effective zone access ('none'|'read'|'write'). $zone is a hashref with {id} or an id.
sub _access {
    my ($self, $zone) = @_;
    return 'write' if $self->_ctx->{allow_all};
    my $zid   = ref($zone) eq 'HASH' ? $zone->{id} : $zone;
    return access_for($self->_ctx, $zid);
}

sub _health {
    my ($self) = @_;
    return API::Response->ok({ status => 'ok', service => 'dns-panel' });
}
# Liveness: the app and handler are alive. No DB/PowerDNS queries (LB liveness probe).
sub _health_live {
    my ($self) = @_;
    return API::Response->json('200 OK', { status => 'live', service => 'dns-panel' });
}
# Readiness: actual node state (panel DB/schema/pdns DB/pdns control + writable). Ready -> 200, otherwise
# (degraded/standby) -> 503 with structured JSON (checks, reason). No session (LB probe).
sub _health_ready {
    my ($self) = @_;
    my $h = node_health();
    return API::Response->json(($h->{ready} ? '200 OK' : '503 Service Unavailable'), $h);
}

# ---- HA: facade over dns-ha-manager ----
#
# No HA checks here: the panel authenticates the user, checks the capability and passes the intent to the
# manager. All substantive refusals ("node is not ACTIVE", "operation in progress", "peer is serving") come
# from it; otherwise a second place would decide the role's fate, and one day the two would diverge.
#
# Capabilities: normal control is ha.manage; emergency promotion and reseed are ha.emergency. The split is
# not a formality: emergency promotion can lose data, and reseed wipes the node and reloads it.
sub _ha_guard {
    my ($self, $cap) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    return (undef, API::Response->forbidden("Capability '$cap' required")) unless has_capability($user, $cap);
    return (undef, API::Response->json('400 Bad Request', { error => 'not_pair', message => 'HA is not in pair mode' }))
        unless ha_mode() eq 'pair';
    return ($user, undef);
}

# Manager reply -> HTTP. Daemon unavailable is 503: "state unknown", not "all good".
# The manager's explanation is passed through as-is; without it the user sees a bare code like `failed`.
sub _ha_reply {
    my ($r, $err, $msg, $ok_status) = @_;
    return API::Response->json('503 Service Unavailable',
        { error => $err, (defined $msg && length $msg ? (message => $msg) : ()) }) if $err;
    return API::Response->json($ok_status || '200 OK', ref $r eq 'HASH' && exists $r->{result} ? $r->{result} : $r);
}

sub _ha_status {
    my ($self) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('status');
    return _ha_reply($r, $e, $m);
}

# Pair configuration. Readable on any node; changed only through the manager, which runs the revision through
# a two-phase protocol. The panel never writes to dns_ha.
sub _ha_config_get {
    my ($self) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('config');
    return _ha_reply($r, $e, $m);
}

# PUT /ha/pair-address: which of THIS node's addresses to give the peer when pairing. Not a manager setting
# (it listens on :7901 on all interfaces); it is a hint on screen. It used to be guessed as the first
# non-loopback address, which turned out to be the LXC bridge. Now the user picks from the node's real addresses.
sub _ha_pair_address_put {
    my ($self) = @_;
    # NOT _ha_guard: that requires pair mode, while this address is needed BEFORE the pair exists.
    my $u = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $u;
    return API::Response->forbidden("Capability 'ha.manage' required") unless has_capability($u, 'ha.manage');
    my ($b, $bad) = _strict_body([qw(address)]); return $bad if $bad;
    my ($ok, $e) = ha_pair_address_set($b->{address});
    return _inv_fail($e) if $e;
    my ($cur) = ha_pair_address();
    audit_log({ actor => $u->{username}, source => 'api', action => 'ha_pair_address_set',
                target_type => 'ha_config', result => 'ok',
                after => { address => ($cur // '') }, ip => get_client_ip() });
    return API::Response->ok({ address => $cur });
}
# Service address and probe port of a running pair. Separate from /ha/config on purpose: the panel does not
# build a revision, it names two values and the manager decides how to apply them. Building the revision here
# would create a second place that knows the pair config layout.
sub _ha_publication_put {
    my ($self) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($b, $bad) = _strict_body([qw(address probe_port)]); return $bad if $bad;
    my %req = (requested_by => $u->{username});
    $req{address}    = $b->{address}    if defined $b->{address} && length $b->{address};
    $req{probe_port} = int($b->{probe_port}) if defined $b->{probe_port} && $b->{probe_port} =~ /^\d+$/;
    my ($r, $e, $m) = ha_manager_request('publication_apply', %req);
    if ($e) {
        my $status = ($e eq 'ha_manager_unavailable' || $e eq 'ha_manager_timeout')
                   ? '503 Service Unavailable' : '409 Conflict';
        audit_log({ actor => $u->{username}, source => 'api', action => 'ha_publication_apply',
                    target_type => 'ha_config', result => 'error', detail => substr(($m // $e), 0, 255),
                    ip => get_client_ip() });
        return API::Response->json($status, { error => $e, (defined $m && length $m ? (message => $m) : ()) });
    }
    my $res = ref $r eq 'HASH' ? ($r->{result} // $r) : $r;
    audit_log({ actor => $u->{username}, source => 'api', action => 'ha_publication_apply',
                target_type => 'ha_config', after => (ref $res eq 'HASH' ? $res : undef), ip => get_client_ip() });
    return API::Response->ok($res);
}

# PUT deliberately goes through the panel's COMMON write gate: pair config is changed by the node currently
# entitled to change it, which is exactly what the gate checks. Exempting it (as for emergency commands) would
# let two nodes edit the config separately, the very divergence the protocol exists to prevent.
sub _ha_config_put {
    my ($self) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($b, $bad) = _strict_body([qw(payload)]); return $bad if $bad;
    return API::Response->bad_request('payload object required') unless ref $b->{payload} eq 'HASH';
    my ($r, $e, $m) = ha_manager_request('config_apply', requested_by => $u->{username}, payload => $b->{payload});
    if ($e) {
        my $status = ($e eq 'ha_manager_unavailable' || $e eq 'ha_manager_timeout')
                   ? '503 Service Unavailable' : '409 Conflict';
        audit_log({ actor => $u->{username}, source => 'api', action => 'ha_config_apply',
                    target_type => 'ha_config', result => 'error', detail => substr(($m // $e), 0, 255),
                    ip => get_client_ip() });
        return API::Response->json($status, { error => $e, (defined $m && length $m ? (message => $m) : ()) });
    }
    my $res = ref $r eq 'HASH' ? ($r->{result} // $r) : $r;
    audit_log({ actor => $u->{username}, source => 'api', action => 'ha_config_apply', target_type => 'ha_config',
                target => (ref $res eq 'HASH' ? $res->{revision} : undef),
                after => (ref $res eq 'HASH' ? $res : undef), ip => get_client_ip() });
    return API::Response->ok($res);
}

# ---- Pairing: available only WHILE there is no pair ----
#
# Own guard instead of _ha_guard, which requires an existing pair. Requires the installed contour (manager on
# this node) and the same ha.manage: "join two servers" is no lighter a decision than a role switch.
sub _ha_pair_guard {
    my ($self) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    return (undef, API::Response->forbidden("Capability 'ha.manage' required"))
        unless has_capability($user, 'ha.manage');
    return (undef, API::Response->json('400 Bad Request',
        { error => 'ha_disabled', message => 'HA contour is not installed on this node' })) unless ha_enabled();
    return ($user, undef);
}

# The human's action goes to the panel audit log (opened the window, approved the peer, built the pair): these
# are decisions someone is accountable for. Technical steps (secrets, GTID, reseed) belong in the HA operation
# history; mixing them would bury decisions in detail.
sub _ha_pair_do {
    my ($self, $cmd, $action, %args) = @_;
    my ($u, $err) = _ha_pair_guard($self); return $err if $err;
    my ($r, $e, $m) = ha_manager_request($cmd, requested_by => $u->{username}, %args);
    if ($e) {
        audit_log({ actor => $u->{username}, source => 'api', action => $action, target_type => 'ha_pair',
                    result => 'error', detail => substr(($m // $e), 0, 255), ip => get_client_ip() });
        my $status = ($e eq 'ha_manager_unavailable' || $e eq 'ha_manager_timeout')
                   ? '503 Service Unavailable' : '409 Conflict';
        return API::Response->json($status, { error => $e, (defined $m && length $m ? (message => $m) : ()) });
    }
    my $res = ref $r eq 'HASH' ? ($r->{result} // $r) : $r;
    audit_log({ actor => $u->{username}, source => 'api', action => $action, target_type => 'ha_pair',
                target => (ref $res eq 'HASH' ? ($res->{peer_node_id} // $res->{receiver} // $res->{state}) : undef),
                after => (ref $res eq 'HASH' ? $res : undef), result => 'ok', ip => get_client_ip() });
    return API::Response->ok($res);
}

sub _ha_pair_status {
    my ($self) = @_;
    my ($u, $err) = _ha_pair_guard($self); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('pair_status');
    return _ha_reply($r, $e, $m);
}

# Inventory of BOTH sides' data, used to choose whose data stays. Read-only, so not audited.
sub _ha_pair_inventory {
    my ($self) = @_;
    my ($u, $err) = _ha_pair_guard($self); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('pair_inventory');
    return _ha_reply($r, $e, $m);
}

sub _ha_pair_create  { my ($self) = @_; return _ha_pair_do($self, 'pair_create',  'ha_pair_open'); }
sub _ha_pair_approve { my ($self) = @_; return _ha_pair_do($self, 'pair_approve', 'ha_pair_approve'); }
sub _ha_pair_reject  { my ($self) = @_; return _ha_pair_do($self, 'pair_reject',  'ha_pair_reject'); }

sub _ha_pair_join {
    my ($self) = @_;
    my ($b, $bad) = _strict_body([qw(address)]); return $bad if $bad;
    my $addr = ref $b eq 'HASH' ? ($b->{address} // '') : '';
    return API::Response->bad_request('address required') unless length $addr;
    return _ha_pair_do($self, 'pair_join', 'ha_pair_join', address => $addr);
}

# Dissolving established trust is an explicit decision, so force must be a real JSON boolean: the string
# "false" is true in Perl, and lenient parsing would turn a refusal into consent.
sub _ha_pair_reset {
    my ($self) = @_;
    my ($b, $bad) = _strict_body([qw(force)]); return $bad if $bad;
    my $f = ref $b eq 'HASH' ? $b->{force} : undef;
    return API::Response->bad_request('force must be a JSON boolean')
        if defined $f && !JSON::is_bool($f);
    return _ha_pair_do($self, 'pair_reset', 'ha_pair_reset', force => ($f && $f ? JSON::true : JSON::false));
}

# Each node has its own publication interface: NIC names on two machines need not match. Shows what each node
# found for the given address. Read-only.
sub _ha_pair_devices {
    my ($self) = @_;
    my ($u, $err) = _ha_pair_guard($self); return $err if $err;
    my $addr = $self->{cgi} ? ($self->{cgi}->param('address') // '') : '';
    return API::Response->bad_request('address required') unless length $addr;
    my ($r, $e, $m) = ha_manager_request('pair_devices', address => $addr);
    return _ha_reply($r, $e, $m);
}

# Pair build. Runs on the DONOR, whose data stays; the other node's data is replaced.
# No interface is accepted AT ALL: each node derives it from its route to the service address. A field for
# typing the other machine's NIC name only surfaces its mistake at the first role switch.
sub _ha_pair_build {
    my ($self) = @_;
    my ($b, $bad) = _strict_body([qw(provider address probe_port)]); return $bad if $bad;
    my $prov = ref $b eq 'HASH' ? ($b->{provider} // '') : '';
    return API::Response->bad_request('provider must be floating_ip, anycast or marker')
        unless $prov =~ /^(floating_ip|anycast|marker)$/;
    my $addr = $b->{address} // '';
    return API::Response->bad_request('address is required for this provider')
        if $prov ne 'marker' && !length $addr;
    # Anycast is published by an open probe port, not an address: the external checker (tcp-connect) only
    # sees "port open / closed". Without a port the pair cannot signal readiness and looks up on both nodes.
    my $probe = $b->{probe_port} // 0;
    if ($prov eq 'anycast') {
        return API::Response->bad_request('probe_port must be a TCP port between 1 and 65535')
            unless $probe =~ /^\d+$/ && $probe >= 1 && $probe <= 65535;
    } else {
        $probe = 0;
    }
    return _ha_pair_do($self, 'pair_build', 'ha_pair_build',
        provider => $prov, address => $addr, ($probe ? (probe_port => $probe + 0) : ()));
}

sub _ha_operations {
    my ($self) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('operations', limit => 20);
    return _ha_reply($r, $e, $m);
}

sub _ha_operation {
    my ($self, $id) = @_;
    my ($u, $err) = _ha_guard($self, 'ha.manage'); return $err if $err;
    my ($r, $e, $m) = ha_manager_request('operation', id => $id);
    return API::Response->not_found("No HA operation '$id'") if $e && $e eq 'failed';
    return _ha_reply($r, $e, $m);
}

# Intent submission: 202 means "accepted, the manager executes it". Not 201: the operation is not done yet.
sub _ha_intent {
    my ($self, $cmd, $cap, $action, %args) = @_;
    my ($u, $err) = _ha_guard($self, $cap); return $err if $err;
    my ($r, $e, $m) = ha_manager_request($cmd, requested_by => $u->{username}, %args);
    if ($e) {
        # A substantive manager refusal (not ACTIVE, operation running, peer serving) is 409: the pair state
        # does not allow it, and retrying without a state change is pointless.
        my $status = ($e eq 'ha_manager_unavailable' || $e eq 'ha_manager_timeout') ? '503 Service Unavailable' : '409 Conflict';
        audit_log({ actor => $u->{username}, source => 'api', action => $action, target_type => 'ha_operation',
                    result => 'error', detail => substr(($m // $e), 0, 255), ip => get_client_ip() });
        return API::Response->json($status, { error => $e, (defined $m && length $m ? (message => $m) : ()) });
    }
    my $res = ref $r eq 'HASH' ? ($r->{result} // $r) : $r;
    audit_log({ actor => $u->{username}, source => 'api', action => $action, target_type => 'ha_operation',
                target => (ref $res eq 'HASH' ? $res->{operation_id} : undef),
                after => $res, result => 'ok', ip => get_client_ip() });
    return API::Response->json('202 Accepted', $res);
}

sub _ha_switchover {
    my ($self) = @_;
    my $body = _json_body() || {};
    return $_[0]->_ha_intent('switchover', 'ha.manage', 'ha_switchover_create', target => ($body->{target} // ''));
}

# accept_relay_loss literally permits DATA LOSS, so only a real JSON boolean is accepted: the string "false"
# is true in Perl, and lenient parsing would turn the operator's refusal into consent.
# Returns (0|1, undef) or (undef, reason); the caller builds the HTTP response.
sub _relay_loss_flag {
    my ($body) = @_;
    my $v = ref $body eq 'HASH' ? $body->{accept_relay_loss} : undef;
    return (0, undef) unless defined $v;
    return ($v ? 1 : 0, undef) if JSON::is_bool($v);
    return (undef, 'accept_relay_loss must be a JSON boolean (true/false)');
}

sub _ha_emergency {
    my ($self) = @_;
    my $body = _json_body();
    return API::Response->bad_request('Invalid or missing JSON body') unless ref $body eq 'HASH';
    return API::Response->bad_request('ack is required') unless defined $body->{ack} && length $body->{ack};
    my ($relay_loss, $ferr) = _relay_loss_flag($body);
    return API::Response->bad_request($ferr) if $ferr;
    return $self->_ha_intent('emergency', 'ha.emergency', 'ha_emergency_promote',
                             ack => $body->{ack}, accept_relay_loss => ($relay_loss ? JSON::true : JSON::false));
}

sub _ha_reseed {
    my ($self) = @_;
    return $self->_ha_intent('reseed', 'ha.emergency', 'ha_reseed');
}

# Pair dismantle. Needs ha.emergency, not ha.manage: it ends the pair, after which the nodes diverge forever.
# The confirmation phrase is checked HERE, not only in the browser: the modal guards against a stray click,
# the server against a request that bypasses the UI.
# The expected phrase is computed here from pair state, never taken from the browser. It names the machines by
# hostname (display names are arbitrary), sorted so it does not depend on which node is ACTIVE.
sub _ha_teardown_phrase {
    my ($st) = @_;
    my $p = (ref $st eq 'HASH' && ref $st->{pair} eq 'HASH') ? $st->{pair} : {};
    my @hosts = sort grep { defined && length }
                map { ref $p->{$_} eq 'HASH' ? $p->{$_}{hostname} : undef } qw(self peer);
    return undef unless @hosts == 2;
    return "dismantle $hosts[0] - $hosts[1]";
}

sub _ha_teardown_check {
    my ($confirm) = @_;
    my ($st, $err) = ha_manager_request('status');
    $st = $st->{result} if ref $st eq 'HASH' && ref $st->{result} eq 'HASH';
    return API::Response->json('503 Service Unavailable',
        { error => ($err // 'ha_manager_unavailable'), message => 'the pair state is unknown' })
        if $err || ref $st ne 'HASH';
    my $want = _ha_teardown_phrase($st);
    return API::Response->json('409 Conflict', { error => 'pair_not_identified',
        message => 'both hostnames must be known before the pair can be dismantled' })
        unless defined $want;
    return API::Response->bad_request("type '$want' to confirm dismantling the pair")
        unless defined $confirm && $confirm eq $want;
    return undef;
}

sub _ha_dismantle {
    my ($self) = @_;
    my ($b, $bad) = _strict_body([qw(confirm)]); return $bad if $bad;
    my $confirm = (ref $b eq 'HASH' ? ($b->{confirm} // '') : '');
    if (my $refused = _ha_teardown_check($confirm)) { return $refused }
    return $self->_ha_intent('dismantle', 'ha.emergency', 'ha_dismantle');
}

# Resume inherits the capability FROM THE OPERATION KIND: continuing an emergency promotion or reseed is the
# same decision as starting it. Consent to losing the relay tail always requires ha.emergency, even if the
# operation kind could not be fetched.
sub _ha_resume {
    my ($self, $id) = @_;
    my $body = _json_body() || {};
    my ($relay_loss, $ferr) = _relay_loss_flag($body);
    return API::Response->bad_request($ferr) if $ferr;

    my ($op, $oe) = ha_manager_request('operation', id => $id);
    my $kind = (ref $op eq 'HASH' && ref $op->{result} eq 'HASH' && ref $op->{result}{operation} eq 'HASH')
             ? ($op->{result}{operation}{kind} // '') : '';

    # Dismantle cannot be resumed at all; that rule lives in the manager (shared by UI, API and CLI) and is
    # not duplicated here.

    my $cap = 'ha.manage';
    if ($relay_loss) {
        $cap = 'ha.emergency';
    } else {
        # Unknown kind (manager unavailable) -> require the HIGHER capability; never guess towards leniency.
        $cap = 'ha.emergency'
            if !length $kind || $kind eq 'emergency_promote' || $kind eq 'reseed' || $kind eq 'dismantle';
    }
    return $self->_ha_intent('resume', $cap, 'ha_operation_resume', id => $id,
                             accept_relay_loss => ($relay_loss ? JSON::true : JSON::false));
}

# Only zones with access != none, each annotated with its computed access.
sub _list_zones {
    my ($self) = @_;
    my $domains = pdns_list_domains();
    my $ctx  = $self->_ctx;
    my @out;
    for my $z (@$domains) {
        my $acc = access_for($ctx, $z->{id});
        next if $acc eq 'none';
        $z->{access} = $acc;
        push @out, $z;
    }
    return API::Response->ok({ zones => \@out });
}

sub _get_zone {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    # none -> 404: do not reveal that the zone exists.
    return API::Response->not_found('Zone not found')
        unless $zone && $self->_access($zone) ne 'none';
    $zone->{access} = $self->_access($zone);
    $zone->{labels} = zone_labels_get($id);
    $zone->{soa}    = pdns_soa_fields($id);
    return API::Response->ok({ zone => $zone });
}

# POST /zones: create a zone. Requires zones.manage (not write access to content).
# body: { name, profile, role('primary'|'secondary'),
#   primary: soa:{primary_ns,hostmaster,ttl,serial,refresh,retry,expire,minimum}, nameservers:[...]
#   secondary: masters:[...], tsig, renotify }
sub _create_zone {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');

    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my ($name, $nerr) = dns_validate_zonename($body->{name});
    return API::Response->bad_request($nerr) if $nerr;

    # Strict role whitelist through the core validator: a typo (seconday/natve) must NOT silently become
    # MASTER. The default applies only when role is ABSENT.
    my ($role, $rlerr)  = zone_role_norm(defined $body->{role} ? lc($body->{role}) : undef);
    return API::Response->bad_request($rlerr) if $rlerr;

    # Profile is a technical SOA/NS preset (separate from labels) and only a convenience: SOA and NS can be
    # set in the form. None selected -> zone without a profile; if selected, it must exist.
    my $profile = $body->{profile};
    $profile = undef unless defined $profile && length $profile;
    if (defined $profile) {
        my %valid = map { $_ => 1 } @{ zone_profile_names() };
        return API::Response->bad_request("unknown profile '$profile'") unless $valid{$profile};
    }

    return API::Response->conflict("Zone '$name' already exists")
        if pdns_get_domain_by_name($name);

    my %opts = (profile => $profile, role => $role);
    my ($tsig_up, $made_up);   # secondary: upstream TSIG, possibly a key created from the form
    my ($after, $d, $derr);
    if ($role eq 'secondary') {
        return API::Response->bad_request('masters must be an array of IP addresses')
            if defined $body->{masters} && ref($body->{masters}) ne 'ARRAY';
        my @masters = grep { defined && length } @{ $body->{masters} || [] };
        return API::Response->bad_request('secondary zone requires at least one master')
            unless @masters;
        # Canonical IPv4/IPv6 only: PowerDNS expects a list of primary addresses in domains.master.
        for my $m (@masters) {
            return API::Response->bad_request("invalid master address '$m' (expected IPv4/IPv6)") unless is_ip_addr($m);
        }
        ($tsig_up, $made_up, my $te) = upstream_tsig_resolve($body->{tsig}, $body->{tsig_new});
        return API::Response->bad_request($te) if $te;
        @opts{qw(masters tsig renotify)} = (\@masters, $tsig_up, ($body->{renotify} ? 1 : 0));
        $after = { name => $name, type => 'SLAVE', role => 'secondary', profile => $profile,
                   masters => \@masters,
                   tsig => $tsig_up, renotify => ($body->{renotify} ? 1 : 0) };
    } else {
        # primary -> MASTER with SOA/NS from the profile preset (the panel never creates NATIVE; see _zone_insert).
        my $ztype = 'MASTER';
        $opts{soa}         = $body->{soa} if ref($body->{soa}) eq 'HASH';
        $opts{nameservers} = $body->{nameservers} if ref($body->{nameservers}) eq 'ARRAY';
        ($d, $derr) = pdns_zone_defaults($name, \%opts);
        return API::Response->bad_request($derr) if $derr;
        $after = { name => $name, type => $ztype, role => $role, profile => $profile,
                   soa => $d->{soa_content}, nameservers => $d->{nameservers} };
    }

    if ($body->{dynamic_profile_id} && $role ne 'primary') { upstream_tsig_rollback($made_up); return API::Response->bad_request('only a primary zone accepts dynamic updates'); }
    my $id = pdns_create_zone($name, \%opts);
    upstream_tsig_rollback($made_up) unless $id;

    # One type-aware activation path: MASTER -> verify (+NOTIFY), NATIVE -> verify (not_applicable),
    # SLAVE -> verify without serial -> pending_transfer (awaits AXFR). Failure does NOT roll back the DB.
    my $sync = $id ? zone_activate_after_create($id) : { pdns_state => 'not_attempted' };

    audit_log({
        actor => $user->{username}, source => 'api',
        action => 'create_zone', target_type => 'zone', target => $name,
        after => { %$after, pdns_state => $sync->{pdns_state}, notify_state => $sync->{notify_state} },
        result => ($id ? 'ok' : 'error'),
        ip => get_client_ip(), request_id => $body->{request_id},
    });
    return API::Response->server_error('Failed to create zone') unless $id;

    # Dynamic updates follow the profile (dynamic_profile_id) via the same core as Zone settings. Custom values
    # are set later in Zone settings; the create form does not duplicate that form.
    my @cwarn = _dyn_on_create($user, $body, [ [ $id, $name ] ]);

    if (ref($body->{labels}) eq 'ARRAY') {
        zone_labels_set($id, $body->{labels}, $user->{username});
    }

    my $zone = pdns_get_domain($id);
    $zone->{profile} = $profile; $zone->{role} = $role;
    $zone->{labels}  = zone_labels_get($id);
    # The zone exists in the DB; PowerDNS activation may still have failed, so report it.
    return API::Response->created({ zone => $zone, pdns_state => $sync->{pdns_state},
                                    notify_state => $sync->{notify_state}, pdns_detail => $sync->{detail},
                                    (@cwarn ? (warnings => \@cwarn) : ()),
                                                                        ($sync->{state_error} ? (state_error => JSON::true) : ()) });
}

# ---- Zone migration from the old master (docs/26) ----
# The export file itself is not kept: it contains the other side's TSIG secrets. Only the parsed zone list is
# stored, once, because migration takes weeks and the screen must remember what was taken and what remains.
sub _import_sources_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($rows, $err) = import_sources_all();
    return _inv_fail($err) if $err;
    return API::Response->ok({ sources => $rows });
}
sub _import_source_load {
    my ($self) = @_;
    my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(master export)]); return $bad if $bad;
    return API::Response->bad_request('export is required') unless defined $b->{export} && length $b->{export};
    # The address is optional: the file itself states it (listen-on). Several candidates -> the user picks.
    my $master = $b->{master};
    unless (defined $master && $master =~ /\S/) {
        my $found = bind_export_sources($b->{export});
        return API::Response->bad_request('source address required'
            . (@$found ? ' (the file mentions: ' . join(', ', @$found) . ')' : '')) unless @$found == 1;
        $master = $found->[0];
    }
    my ($src, $err) = import_source_load($master, $b->{export});
    return API::Response->bad_request($err) if $err;
    _inv_audit($user, 'import_source_load', 'legacy_dns', $src->{master},
               { after => { zones => $src->{zone_count}, added => $src->{added}, changed => $src->{updated} } });
    return API::Response->ok($src);
}
sub _import_inventory {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($inv, $err) = import_inventory($id);
    return _inv_fail($err) if $err;
    return API::Response->ok($inv);
}
sub _import_zone_mark {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(status note)]); return $bad if $bad;
    my ($ok, $err) = import_zone_mark($id, $b->{status}, $b->{note});
    return _inv_fail($err) if $err;
    return API::Response->ok({ marked => JSON::true, id => $id + 0, status => $b->{status} });
}

# POST /zones/import/sources: addresses the old server listened on (listen-on in its own export).
# Asked as soon as a file is chosen; parsing the same file again in JavaScript would mean two parsers of one format.
sub _zone_import_sources {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden('zones.manage required') unless has_capability($user, 'zones.manage');
    my ($b, $bad) = _strict_body([qw(export)]); return $bad if $bad;
    return API::Response->bad_request('export is required')
        unless defined $b->{export} && length $b->{export};
    return API::Response->ok({ sources => bind_export_sources($b->{export}) });
}
# Creates the chosen zones via the same write path as "Add zone", one by one, with a per-zone answer: out of
# three hundred zones some will fail, and all-or-nothing would roll back the good ones for one bad one.
sub _zone_import_apply {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden('zones.manage required') unless has_capability($user, 'zones.manage');
    my ($b, $bad) = _strict_body([qw(source_id tsig tsig_new zones)]); return $bad if $bad;
    return API::Response->bad_request('zones must be an array') unless ref($b->{zones}) eq 'ARRAY';
    # Where zones come from and what each was on the old server (type, own masters, dynamic, signed) is taken
    # from the stored list by source_id. The browser sends only names: the export server address is where the
    # panel will fetch from, and a request must not choose it.
    return API::Response->bad_request('source_id is required') unless $b->{source_id};
    return API::Response->bad_request('tsig_new must be an object with name, algorithm and secret')
        if defined $b->{tsig_new} && ref($b->{tsig_new}) ne 'HASH';
    my ($res, $err) = zone_import_apply($b->{zones}, { tsig => $b->{tsig},
                                                       tsig_new => $b->{tsig_new},
                                                       source_id => $b->{source_id} });
    return API::Response->bad_request($err) if $err;
    # The key is created here, so it is audited here, before the zones (no secret in the record). A key removed
    # right after is a second record, not a missing first one: it did exist.
    if (my $k = $res->{tsig_created}) {
        _inv_audit($user, 'tsig_key_create', 'tsig_key', $k->{id},
                   { after => { name => $k->{name}, algorithm => $k->{algorithm} }, detail => 'created for zone import' });
        # The key can go away even on a fully successful import: zones the old server itself slaved don't get it.
        _inv_audit($user, 'tsig_key_delete', 'tsig_key', $k->{id},
                   { before => { name => $k->{name} }, detail => 'created for import but unused' }) if $res->{tsig_removed};
    }
    # The old server address as used by the core (read from the stored list).
    my $source = $res->{source};
    # One audit record PER zone, with the same action as a normal create: otherwise a zone's appearance can't
    # be found by its name, which is how it is searched for later.
    my $ip = get_client_ip();
    for my $z (@{ $res->{created} }) {
        audit_log({ actor => $user->{username}, source => 'api', action => 'create_zone',
                    target_type => 'zone', target => $z->{name},
                    after => { name => $z->{name}, type => 'SLAVE', role => 'secondary',
                               # What the zone ACTUALLY has: a zone the old server itself slaved keeps its
                               # own masters and empty TSIG, not the form fields.
                               masters => $z->{masters}, tsig => $z->{tsig},
                               imported_from => $source, pdns_state => $z->{pdns_state} },
                    result => 'ok', ip => $ip });
    }
    for my $f (@{ $res->{failed} }) {
        audit_log({ actor => $user->{username}, source => 'api', action => 'create_zone',
                    target_type => 'zone', target => $f->{name},
                    after => { imported_from => $source },
                    result => 'error', detail => $f->{error}, ip => $ip });
    }
    # Plus the migration itself: "the batch from server X" is a question not asked about a single zone.
    audit_log({ actor => $user->{username}, source => 'api', action => 'import_zones',
                target_type => 'legacy_dns', target => ($source // ''),
                after => { source => $source,
                           created => scalar @{ $res->{created} }, failed => scalar @{ $res->{failed} },
                           skipped => scalar @{ $res->{skipped} } },
                result => (@{ $res->{failed} } ? 'partial' : 'ok'), ip => $ip });
    return API::Response->ok($res);
}

# GET /zones/defaults[?profile=]: data for the Add zone form (zones.manage).
# Without profile: profiles/roles + catalogs. With profile: its primary preset (NS/SOA).
sub _zone_defaults {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');
    my $q = $self->{cgi};
    # SOA timers are no longer global: they belong to the profile and come in the preset.
    my %out = (
        profiles => zone_profiles_for_form(),   # [{code,name}]: value=code, label=name
        roles  => [ 'primary', 'secondary' ],
        # Same fields as the zone settings form (pages/records.pl -> zs-cat-data): the catalog is chosen by ITS
        # name (FQDN), not the Distribution name, which may coincide. provisioned lets the UI say "still being created".
        catalogs => [ map { { catalog_id => $_->{catalog_id}, name => $_->{name}, fqdn => $_->{fqdn},
                              provisioned => ($_->{provisioned} ? JSON::true : JSON::false) } }
                      @{ (catalogs_available())[0] || [] } ],
        # Same capability as the route itself (_zcatalog_set): listing a zone in a catalog is a DISTRIBUTION decision.
        can_change_catalog => ((has_capability($user, 'zones.manage') && has_capability($user, 'distribution.manage')) ? JSON::true : JSON::false),
    );
    my $profile = $q ? $q->param('profile') : undef;
    if (defined $profile && length $profile) {
        my ($p, $perr) = zone_profile_preset($profile);
        return API::Response->bad_request($perr) if $perr;
        $out{profile} = $profile;
        $out{preset}  = { primary_ns => $p->{primary_ns}, hostmaster => $p->{hostmaster},
                          nameservers => $p->{nameservers},
                          soa => { ttl => $p->{ttl}, refresh => $p->{refresh}, retry => $p->{retry},
                                   expire => $p->{expire}, minimum => $p->{minimum} },
                          default_catalog_id => $p->{default_catalog_id} };
    }
    return API::Response->ok(\%out);
}

# GET /audit: global log with filters (actor/action/result/target_type/source + target LIKE) and paging. audit.read.
sub _audit_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_cap_ok('audit.read'); return $deny if $deny;
    my $q = $self->{cgi};
    my %f;
    for my $k (qw(actor action result target_type source target from to)) {
        my $v = $q ? $q->param($k) : undef;
        $f{$k} = $v if defined $v && length $v;
    }
    # Normalise limit/offset HERE and return the values ACTUALLY applied, or the UI would page by wrong values.
    my $limit  = ($q && defined $q->param('limit'))  ? $q->param('limit')  : 50;
    my $offset = ($q && defined $q->param('offset')) ? $q->param('offset') : 0;
    $limit  = 50 unless $limit  =~ /^\d+$/ && $limit > 0 && $limit <= 500;
    $offset = 0  unless $offset =~ /^\d+$/;
    my ($rows, $total) = audit_search(\%f, $limit, $offset);
    return API::Response->ok({ rows => $rows, total => $total, limit => $limit + 0, offset => $offset + 0 });
}

# ---- Zone profiles CRUD (Settings -> Zone profiles), all under zones.manage ----
sub _zp_auth { my ($self) = @_; my $u = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $u;
    return (undef, API::Response->forbidden("Capability 'zones.manage' required")) unless has_capability($u, 'zones.manage');
    return ($u, undef); }
sub _zp_list {
    my ($self) = @_; my ($u, $deny) = _zp_auth($self); return $deny if $deny;
    my ($rows, $err) = zone_profiles_all(); return _inv_fail($err) if $err;
    return API::Response->ok({ profiles => $rows });
}
sub _zp_get {
    my ($self, $id) = @_; my ($u, $deny) = _zp_auth($self); return $deny if $deny;
    my ($p, $err) = zone_profile_get($id); return _inv_fail($err) if $err;
    return API::Response->ok({ profile => $p });
}
sub _zp_create {
    my ($self) = @_; my ($u, $deny) = _zp_auth($self); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(code name enabled preset)]); return $bad if $bad;
    my ($id, $err) = zone_profile_create($b); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_profile_create', 'zone_profile', $id, { after => { code => $b->{code}, name => $b->{name} } });
    return API::Response->created({ id => $id + 0 });
}
sub _zp_update {
    my ($self, $id) = @_; my ($u, $deny) = _zp_auth($self); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(code name enabled preset)], patch => 1); return $bad if $bad;
    my ($ok, $err) = zone_profile_update($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_profile_update', 'zone_profile', $id, { detail => { fields => [ sort keys %$b ] } });
    return API::Response->ok({ updated => JSON::true, id => $id + 0 });
}
sub _zp_delete {
    my ($self, $id) = @_; my ($u, $deny) = _zp_auth($self); return $deny if $deny;
    my $label = audit_target_label('zone_profile', $id);   # name snapshot BEFORE deletion
    my ($ok, $err) = zone_profile_delete($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_profile_delete', 'zone_profile', $id, { label => $label });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}

# GET /reverse/preview?cidr=: reverse zone plan with statuses (exists/covered/missing). zones.manage.
sub _reverse_preview {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');
    my $q = $self->{cgi};
    my ($plan, $err) = reverse_plan_for_cidr($q ? $q->param('cidr') : undef);
    return API::Response->bad_request($err) if $err;
    return API::Response->ok($plan);
}

# POST /reverse: create ONLY the missing /24 zones of a network (atomically). zones.manage.
# body: { cidr, profile, covered_action, soa=>{overrides}?, nameservers=>[...]?, labels=>[...]? }.
# Existing/covered zones are left alone. soa/nameservers, if given, apply to ALL created zones;
# labels are assigned to each zone actually created.
sub _create_reverse {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my ($plan, $err) = reverse_plan_for_cidr($body->{cidr});
    return API::Response->bad_request($err) if $err;

    my $profile = $body->{profile};
    $profile = undef unless defined $profile && length $profile;   # optional: SOA/NS may come from the form
    if (defined $profile) {
        my %valid = map { $_ => 1 } @{ zone_profile_names() };
        return API::Response->bad_request("unknown profile '$profile'") unless $valid{$profile};
    }
    # covered_action: 'use_parent' (default: nothing created, PTRs go to the parent) | 'create' (/24 + delegation)
    my $cov = ($body->{covered_action} && $body->{covered_action} eq 'create') ? 'create' : 'use_parent';

    # Base opts for every created zone; soa/nameservers are an optional override (otherwise
    # pdns_zone_defaults uses the profile preset per zone). Refs are read-only, so shared between specs.
    my %base_opts = (profile => $profile, role => 'primary');
    $base_opts{soa}         = $body->{soa}         if ref($body->{soa}) eq 'HASH';
    $base_opts{nameservers} = $body->{nameservers} if ref($body->{nameservers}) eq 'ARRAY' && @{ $body->{nameservers} };

    my @specs;
    for my $z (@{ $plan->{zones} }) {
        if ($z->{status} eq 'missing') {
            push @specs, { name => $z->{name}, opts => { %base_opts } };
        } elsif ($z->{status} eq 'covered' && $cov eq 'create') {
            push @specs, { name => $z->{name}, opts => { %base_opts },
                           delegate_parent => $z->{covered_by} };
        }
    }
    return API::Response->ok({ created => [], skipped => $plan->{zones}, message => 'Nothing to create' })
        unless @specs;

    my ($ids, $berr, $parents) = pdns_create_zones_batch(\@specs);
    return API::Response->server_error("Batch create failed: $berr") unless $ids;

    # Labels on each zone actually created (ids follow @specs order).
    if (ref($body->{labels}) eq 'ARRAY' && @{ $body->{labels} }) {
        for my $i (0 .. $#specs) {
            zone_labels_set($ids->[$i], $body->{labels}, $user->{username}) if $ids->[$i];
        }
    }

    # ONE rediscover for the whole batch, then verify each created zone; delegating parents get purge+notify.
    dns_agent_call('rediscover');
    my @sync;                                  # per-zone sync (created + parents) for the response
    for my $s (@specs) {
        my $v = zone_verify($s->{name});
        my $sok = set_zone_sync_state($s->{name}, $v->{pdns_state}, $v->{notify_state}, $v->{detail});
        $v->{state_error} = 1 unless $sok;
        push @sync, { zone => $s->{name}, %{ _sync_payload($v) } };
    }
    # Dynamic updates for all created zones (migrated dynamic zones are mostly reverse /24s). After rediscover:
    # the PowerDNS API writes metadata only for a zone it already knows.
    my @dwarn = _dyn_on_create($user, $body, [ map { [ $ids->[$_], $specs[$_]{name} ] } grep { $ids->[$_] } 0 .. $#specs ]);
    # Parents got a delegation (NS + SOA bump) -> verified sync against the parent's serial (is the NS cut visible yet).
    for my $p (@{ $parents || [] }) {
        my $v = _post_write_sync($p->{name}, $p->{serial});
        push @sync, { zone => $p->{name}, %{ _sync_payload($v) } };
    }

    audit_log({ actor => $user->{username}, source => 'api', action => 'create_reverse_zones',
                target_type => 'zone', target => $body->{cidr},
                after => { created => [ map { $_->{name} } @specs ], profile => $profile,
                           delegated_parents => [ map { $_->{name} } @{ $parents || [] } ],
                           labels => (ref($body->{labels}) eq 'ARRAY' ? $body->{labels} : []),
                           dynamic_profile_id => $body->{dynamic_profile_id},
                           soa_override => (ref($body->{soa}) eq 'HASH' ? \1 : \0) },
                result => 'ok', ip => get_client_ip() });
    return API::Response->created({ created => [ map { { id => ($ids->[$_] ? $ids->[$_] + 0 : undef), name => $specs[$_]{name} } } 0 .. $#specs ], count => scalar(@specs),
                                    delegated_parents => [ map { $_->{name} } @{ $parents || [] } ],
                                    sync => \@sync,
                                    (@dwarn ? (warnings => \@dwarn) : ()),
                                    skipped => [ grep { $_->{status} eq 'exists' || ($_->{status} eq 'covered' && $cov ne 'create') } @{ $plan->{zones} } ] });
}

# DELETE /zones/:id: delete a zone. zones.manage + confirmation by exact name.
# body: { confirm_name }. Audit "before" is the full snapshot of what was destroyed.
sub _delete_zone {
    my ($self, $id) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');

    my $body = _json_body() || {};
    my $confirm = $body->{confirm_name};
    return API::Response->bad_request("confirm_name must equal zone name '$zone->{name}'")
        unless defined $confirm && lc($confirm) eq lc($zone->{name});

    # Read the key the zone used to sign AXFR from its primary BEFORE deleting: the reference disappears
    # with the zone, and the key can't be found by name afterwards.
    my $meta0 = pdns_get_domain_metadata($id) || {};
    my $up_tsig = ($meta0->{'AXFR-MASTER-TSIG'} && @{ $meta0->{'AXFR-MASTER-TSIG'} }) ? $meta0->{'AXFR-MASTER-TSIG'}[0] : '';

    # Full deletion is a shared core function: the site and MCP must have a single path.
    my ($res, $derr) = zone_delete_everywhere($id + 0);
    my $ok = $res ? 1 : 0;
    my $snapshot = $res ? $res->{snapshot} : pdns_zone_snapshot($id);
    my $sync = $res ? $res->{sync} : { pdns_state => 'not_attempted' };
    if ($res) {
        $sync->{cleanup_error} = $res->{cleanup_error} if $res->{cleanup_error};
        $sync->{state_error}   = 1 if $res->{state_error};
    }
    audit_log({
        actor => $user->{username}, source => 'api',
        action => 'delete_zone', target_type => 'zone', target => $zone->{name},
        before => $snapshot, after => { pdns_state => $sync->{pdns_state} },
        # Zone removed from PowerDNS but panel cleanup failed -> 'partial', not 'ok'.
        result => (!$ok ? 'error' : ($sync->{cleanup_error} ? 'partial' : 'ok')),
        detail => ($sync->{cleanup_error} ? "distribution cleanup failed: $sync->{cleanup_error}" : undef),
        ip => get_client_ip(), request_id => $body->{request_id},
    });
    return API::Response->server_error('Failed to delete zone') unless $ok;
    my %out = ( deleted => JSON::true, id => $id + 0, name => $zone->{name},
                pdns_state => $sync->{pdns_state},
                ($sync->{state_error} ? (state_error => JSON::true) : ()),
                ($sync->{cleanup_error} ? (cleanup_error => $sync->{cleanup_error}) : ()) );
    _tsig_sweep($user, \%out, $up_tsig);   # zone gone: its upstream key may now have no references
    return API::Response->ok(\%out);
}

# PATCH /zones/:id: zone settings (profile). zones.manage.
# body: { profile? }. Changes ONLY the binding (panel metadata); SOA/NS are NOT rewritten automatically.
# Role/type are not changed here: primary<->secondary is a separate operation.
sub _patch_zone {
    my ($self, $id) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    return API::Response->forbidden("Capability 'zones.manage' required")
        unless has_capability($user, 'zones.manage');
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');

    my $before = { profile => (pdns_profile_map($id)->{$id}) };
    my (%changes, @writes);

    if (exists $body->{profile}) {
        # Empty (null/'') clears the profile: after creation it is only a binding, and a wrong one (on a
        # migrated or promoted zone) must be removable, not only replaceable.
        my $profile = $body->{profile};
        $profile = undef unless defined $profile && length $profile;
        if (defined $profile) {
            my %valid = map { $_ => 1 } @{ zone_profile_names() };
            return API::Response->bad_request("unknown profile '$profile'") unless $valid{$profile};
        }
        if (($before->{profile} // '') ne ($profile // '')) {
            push @writes, [ 'X-DNSPANEL-PROFILE', $profile ];
            $changes{profile} = $profile;
        }
    }
    if (@writes) {
        pdns_set_zone_metas($id, \@writes)
            or return API::Response->server_error('Failed to update zone settings');
    }

    audit_log({
        actor => $user->{username}, source => 'api',
        action => 'update_zone_settings', target_type => 'zone', target => $zone->{name},
        before => $before, after => { %$before, %changes }, result => 'ok',
        ip => get_client_ip(), request_id => $body->{request_id},
    }) if %changes;

    my $out = pdns_get_domain($id);
    $out->{profile} = pdns_profile_map($id)->{$id};
    $out->{labels}  = zone_labels_get($id);
    return API::Response->ok({ zone => $out, changed => [ sort keys %changes ] });
}

sub _zone_stats {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    return API::Response->not_found('Zone not found')
        unless $zone && $self->_access($zone) ne 'none';
    my $stats = pdns_count_records_by_type($id);
    my $hosts = pdns_list_subnames($id);
    return API::Response->ok({
        zone       => $zone->{name},
        total      => $stats->{total},
        by_type    => $stats->{by_type},
        host_count => scalar(@$hosts),
    });
}

# Zone subdomains (hosts) plus delegated child zones. Optional ?type=A
sub _zone_subdomains {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    return API::Response->not_found('Zone not found')
        unless $zone && $self->_access($zone) ne 'none';
    my $type  = $self->{cgi} ? $self->{cgi}->param('type') : undef;
    my $hosts = pdns_list_subnames($id, $type);
    my @sub = grep { lc($_->{name}) ne lc($zone->{name}) } @$hosts;
    # Delegated child zones: only those the user can access (don't reveal no-access zones).
    my $children = pdns_list_child_zones($zone->{name});
    my $ctx = $self->_ctx;
    unless ($ctx->{allow_all}) {
        $children = [ grep { access_for($ctx, $_->{id}) ne 'none' } @$children ];
    }
    return API::Response->ok({
        zone            => $zone->{name},
        subdomain_count => scalar(@sub),
        subdomains      => \@sub,
        delegated_zones => $children,
    });
}

# Zone/record propagation check across master and slaves. Optional ?name= &type=
sub _zone_propagation {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    return API::Response->not_found('Zone not found')
        unless $zone && $self->_access($zone) ne 'none';
    my $q = $self->{cgi};
    my $r = dns_check_propagation($zone->{name},
        ($q ? $q->param('name') : undef), ($q ? $q->param('type') : undef));
    return API::Response->bad_request($r->{error}) if $r->{error};
    return API::Response->ok($r);
}

# Record search across all zones. ?q=<substr> &field=name|content|any &type= &limit=
sub _search_records {
    my ($self) = @_;
    my $q = $self->{cgi};
    my $query = $q ? $q->param('q') : undef;
    return API::Response->bad_request('q is required') unless defined $query && length $query;
    $query = dns_name_ascii($query);       # IDN: PowerDNS keeps punycode
    # Allowed zones are filtered IN SQL (before LIMIT) so accessible matches are not lost.
    my $ctx = $self->_ctx;
    my $domain_ids;                       # undef = no restriction (allow_all)
    unless ($ctx->{allow_all}) {
        my $domains = pdns_list_domains();
        $domain_ids = [ grep { access_for($ctx, $_) ne 'none' } map { $_->{id} } @$domains ];
        return API::Response->ok({ query => $query, count => 0, records => [] })
            unless @$domain_ids;
    }
    # IP query: besides the substring, also look up the PTR, whose name is the reversed address and is not
    # found by substring. The core computes it (reverse_candidates_for_ip), not here or in the browser, so the
    # ip6.arpa format matches the one the panel WRITES PTRs with.
    # A partial address ("10.99") matches PTRs by reverse-name suffix; a full address uses the exact name.
    my $ptr_suffix = ptr_suffix_for_partial_ip($query);
    my ($ptr_name, $ref_names);
    if (is_ip_addr($query)) {
        ($ptr_name) = reverse_candidates_for_ip($query);
        # ONE level of references: names holding exactly this address, plus whatever points at them
        # (CNAME/MX/SRV/NS) - "where is this address used". Same scope (accessible zones), or a reference from
        # a visible zone would leak a name from an invisible one.
        $ref_names = pdns_names_with_address($query, $domain_ids);
    }
    my $recs = pdns_search_records($query, {
        # scalar is required: in list context CGI::param returns ALL values (an empty list when absent),
        # which shifted the key/value pairs so `type` became 'limit' and the search found nothing.
        field => (scalar($q->param('field')) || 'any'),
        type  => scalar $q->param('type'),
        limit => scalar $q->param('limit'),
        domain_ids => $domain_ids,
        ip         => (is_ip_addr($query) ? $query : undef),
        extra_name => $ptr_name,
        ref_names  => $ref_names,
        ptr_suffix => $ptr_suffix,
    });
    # IDN names as they are read; the punycode stays in name/zone.
    for my $r (@$recs) {
        for my $k (qw(name zone)) {
            my $u = dns_name_unicode($r->{$k});
            $r->{"${k}_unicode"} = $u if defined $u && $u ne ($r->{$k} // '');
        }
    }
    return API::Response->ok({ query => $query, count => scalar(@$recs), records => $recs,
                               (defined $ptr_name ? (ptr_name => $ptr_name) : ()),
                               # Owner names of the address: lets the UI explain WHY a CNAME without the
                               # address in its text is shown.
                               (($ref_names && @$ref_names) ? (ref_names => $ref_names) : ()),
                               # Network the PTRs were matched by: explains a record whose text lacks "10.99".
                               (defined $ptr_suffix ? (ptr_network => $query) : ()) });
}

# Live DNS query. ?name= &type= &server= &port=
sub _dns_query {
    my ($self) = @_;
    my $q = $self->{cgi};
    my $name = $q ? $q->param('name') : undef;
    return API::Response->bad_request('name is required') unless defined $name && length $name;
    my $r = dns_query($name, $q->param('type'), $q->param('server'), $q->param('port'));
    return API::Response->bad_request($r->{error}) if $r->{error};
    return API::Response->ok($r);
}

# GET /labels: label taxonomy (categories + values) for forms, filters and settings.
sub _list_labels {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->ok({ categories => label_categories_all() });
}

# Taxonomy management requires labels.manage.
sub _labels_admin_ok {
    my ($self) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    return (undef, API::Response->forbidden("Capability 'labels.manage' required"))
        unless has_capability($user, 'labels.manage');
    return ($user, undef);
}

sub _create_label_category {
    my ($self) = @_;
    my ($user, $deny) = $self->_labels_admin_ok; return $deny if $deny;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my ($id, $err) = label_category_create($body->{name}, $body->{cardinality});
    return API::Response->conflict($err) if $err && $err =~ /already exists/;
    return API::Response->bad_request($err) if $err;
    audit_log({ actor => $user->{username}, source => 'api', action => 'label_category_create',
                target_type => 'label_category', target => $body->{name},
                after => { cardinality => ($body->{cardinality} || 'multiple') }, result => 'ok', ip => get_client_ip() });
    return API::Response->created({ id => $id + 0 });
}

sub _delete_label_category {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_labels_admin_ok; return $deny if $deny;
    my $label = audit_target_label('label_category', $id);   # name snapshot BEFORE deletion
    # Confirmation comes as a query parameter: DELETE has no body.
    my $q_lc = $self->{cgi};
    my $lbl_confirm = ($q_lc && defined $q_lc->param('confirm') && $q_lc->param('confirm') eq '1') ? 1 : 0;
    my ($ok, $err) = label_category_delete($id);
    return API::Response->bad_request($err) if $err;
    audit_log({ actor => $user->{username}, source => 'api', action => 'label_category_delete',
                target_type => 'label_category', target => $id, target_label => $label, result => 'ok', ip => get_client_ip() });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}

sub _create_label_value {
    my ($self) = @_;
    my ($user, $deny) = $self->_labels_admin_ok; return $deny if $deny;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my ($id, $err) = label_value_create($body->{category_id}, $body->{name}, $body->{color});
    return API::Response->conflict($err) if $err && $err =~ /already exists/;
    return API::Response->bad_request($err) if $err;
    audit_log({ actor => $user->{username}, source => 'api', action => 'label_value_create',
                target_type => 'label_value', target => $body->{name},
                after => { category_id => $body->{category_id}, color => $body->{color} }, result => 'ok', ip => get_client_ip() });
    return API::Response->created({ id => $id + 0 });
}

sub _delete_label_value {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_labels_admin_ok; return $deny if $deny;
    my $label = audit_target_label('label_value', $id);   # name snapshot BEFORE deletion
    # Confirmation comes as a query parameter: DELETE has no body.
    my $q_lc = $self->{cgi};
    my $lbl_confirm = ($q_lc && defined $q_lc->param('confirm') && $q_lc->param('confirm') eq '1') ? 1 : 0;
    my ($ok, $err) = label_value_delete($id);
    return API::Response->bad_request($err) if $err;
    audit_log({ actor => $user->{username}, source => 'api', action => 'label_value_delete',
                target_type => 'label_value', target => $id, target_label => $label, result => 'ok', ip => get_client_ip() });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}

# --- Write helpers (RRset) ---

# Request JSON body (from $ENV{POST_DATA}, see api.pl): hashref or undef.
sub _json_body {
    my $raw = $ENV{'POST_DATA'};
    return undef unless defined $raw && length $raw;
    my $data = eval { decode_json($raw) };
    return (ref($data) eq 'HASH') ? $data : undef;
}

sub _current_user {
    my ($self) = @_;
    return $self->{user};   # resolved once in api.pl (RequestContext)
}

# Record FQDN relative to the zone: '@' or empty -> the zone; relative -> appended to the zone.
sub _fqdn {
    my ($name, $zone) = @_;
    $name = '' unless defined $name;
    $name =~ s/\s+//g; $name =~ s/\.$//;
    return $zone if $name eq '' || $name eq '@';
    my ($ln, $lz) = (lc $name, lc $zone);
    return $name if $ln eq $lz || $ln =~ /\.\Q$lz\E$/;
    return "$name.$zone";
}

# GET /zones/:id/audit?name=&type=: RRset change history from audit_log. Requires zone access.
sub _zone_audit {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    my $acc  = $zone ? $self->_access($zone) : 'none';
    return API::Response->not_found('Zone not found') if !$zone || $acc eq 'none';
    my $q = $self->{cgi};
    my $name = $q ? $q->param('name') : undef;
    my $type = $q ? uc($q->param('type') || '') : '';
    return API::Response->bad_request('name and type are required')
        unless defined $name && length $name && length $type;
    my $target = _fqdn($name, $zone->{name}) . ' ' . $type;
    return API::Response->ok({ target => $target, history => audit_history('rrset', $target, 50) });
}

# GET /zones/:id/rrsets: zone RRsets (unit = name+type).
sub _list_rrsets {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    my $acc  = $zone ? $self->_access($zone) : 'none';
    return API::Response->not_found('Zone not found') if !$zone || $acc eq 'none';
    return API::Response->ok({ zone => $zone->{name}, access => $acc, rrsets => pdns_list_rrsets($id) });
}

# GET /zones/:id/ptr-status: PTR status of every A/AAAA in a forward zone (batched, no N+1).
# Per record: ok|missing|different|disabled|external|error. Reverse zone not accessible or not local -> external.
sub _zone_ptr_status {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id);
    my $acc  = $zone ? $self->_access($zone) : 'none';
    return API::Response->not_found('Zone not found') if !$zone || $acc eq 'none';
    my $res = zone_ptr_statuses($self->_ctx, $id);   # prebuilt access context, no repeated queries
    return API::Response->ok({ zone => $zone->{name}, statuses => $res->{rows},
                              ($res->{error} ? (error => $res->{error}) : ()) });
}

# GET /sync/problems: zones with activation_failed/notify_failed, filtered by access (+domain_id).
sub _sync_problems {
    my ($self) = @_;
    my $ctx = $self->_ctx;
    my ($probs, $err) = sync_problem_zones();
    return API::Response->server_error("sync state unavailable: $err") if $err;   # don't hide a DB failure as "no problems"
    my @out;
    for my $p (@$probs) {
        my ($dom, $derr) = pdns_find_domain_by_name($p->{zone_name});   # strict: an error is not "no such zone"
        return API::Response->server_error("zone lookup failed: $derr") if $derr;
        if ($dom) {
            my $acc = access_for($ctx, $dom->{id});
            next if $acc eq 'none';
            push @out, { %$p, id => $dom->{id}, type => $dom->{type}, access => $acc };
        } else {
            # Not in pdns.domains (deactivate problem: deleted, but PowerDNS still serves it). Per-zone access
            # can't be checked, so only users who see everything (allow_all) get it.
            next unless $ctx->{allow_all};
            push @out, { %$p, id => undef, access => 'write' };
        }
    }
    return API::Response->ok({ problems => \@out });
}

# POST /zones/:id/retry-sync: retry zone activation/NOTIFY (Retry now). Requires WRITE access.
# Mutual exclusion with the worker is in the core (GET_LOCK). SLAVE is not blocked (it has its own pending_transfer).
sub _retry_sync {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';

    my $res = retry_zone_activation($zone->{name}, {
        actor => $user->{username}, source => 'panel', ip => get_client_ip() });
    return API::Response->ok({ zone => $zone->{name}, busy => JSON::true }) if $res->{busy};
    # State changed concurrently (e.g. the zone was recreated): the frontend just reloads the list.
    return API::Response->ok({ zone => $zone->{name}, superseded => JSON::true }) if $res->{superseded};
    # Check persistence errors BEFORE the ordinary retry error, or state_error would be masked.
    if ($res->{state_error} || $res->{audit_error}) {
        my $m = 'Zone re-activation ran, but persisting sync state failed'
              . ($res->{audit_error} ? ' (state+audit)' : ' (state)')
              . ' - no automatic retry scheduled; check the state database';
        $m .= "; retry error: $res->{error}" if $res->{error};
        return API::Response->server_error($m);
    }
    # Infrastructure error (lookup/SOA/agent): the user sent nothing wrong, so 500, not 400.
    return API::Response->server_error("Retry failed: $res->{error}") if $res->{error};
    return API::Response->ok({ zone => $zone->{name}, serial => $res->{serial},
        sync => { pdns_state => $res->{pdns_state}, notify_state => $res->{notify_state}, detail => $res->{detail} } });
}

# ============================================================================
# DYNAMIC UPDATES (RFC 2136): settings live on each zone; Dynamic DHCP profiles are saved settings a zone can
# follow. All under zones.manage. A new key created in the form gets its own tsig_key_create audit record, as
# everywhere the panel creates a key.
# ============================================================================
# Turn on dynamic updates for freshly created zones per the profile. $zones = [[id, name], ...]. Returns warnings.
sub _dyn_on_create {
    my ($user, $body, $zones) = @_;
    my $pid = $body->{dynamic_profile_id};
    return () unless defined $pid && length $pid;
    my @w;
    for my $z (@$zones) {
        my ($r, $e) = zone_dynamic_save($z->[0], { enabled => 1, profile_id => $pid });
        if ($e) { push @w, "$z->[1]: dynamic updates were not turned on: $e"; next }
        push @w, map { "$z->[1]: $_" } @{ $r->{warnings} || [] };
        _inv_audit($user, 'zone_dynamic_set', 'zone', $z->[1], { after => { enabled => 1, profile => $r->{profile} } });
    }
    return @w;
}
# A new or changed key gets its own audit record (without the secret).
sub _dyn_key_audit {
    my ($u, $kc, $what) = @_;
    return unless $kc;
    _inv_audit($u, ($kc->{created} ? 'tsig_key_create' : 'tsig_key_update'), 'tsig_key', $kc->{id},
               { after => { name => $kc->{name}, algorithm => $kc->{algorithm} },
                 detail => ($kc->{created} ? "created for $what" : "secret changed for $what") });
}
sub _dynp_list {
    my ($self) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($p, $e) = dyn_profiles_all(); return _inv_fail($e) if $e;
    return API::Response->ok({ profiles => $p });
}
sub _dynp_save {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name cidrs key)]); return $bad if $bad;
    my ($r, $e) = dyn_profile_save($id, $b); return _inv_fail($e) if $e;
    _dyn_key_audit($u, $r->{key_change}, 'a dynamic DHCP profile');
    _inv_audit($u, (defined $id ? 'dyn_profile_update' : 'dyn_profile_create'), 'dyn_profile', $r->{id},
               { label => $r->{name}, after => { name => $r->{name}, mode => $r->{mode}, cidrs => $b->{cidrs},
                                                  key => (ref $b->{key} eq 'HASH' ? $b->{key}{name} : undef), zones_updated => $r->{zones} } });
    return defined $id ? API::Response->ok($r) : API::Response->created($r);
}
sub _dynp_create { my ($self) = @_; return $self->_dynp_save(undef); }
sub _dynp_update { my ($self, $id) = @_; return $self->_dynp_save($id); }
sub _dynp_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($r, $e) = dyn_profile_delete($id); return _inv_fail($e) if $e;
    _inv_audit($u, 'dyn_profile_delete', 'dyn_profile', $r->{id},
               { label => $r->{name}, before => { name => $r->{name} }, detail => "$r->{detached} zone(s) keep their settings" });
    return API::Response->ok($r);
}
# GET /zones/:id/dynamic: zone settings plus profiles and keys for the form.
sub _zone_dynamic_get {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($z, $e) = zone_dynamic_get($id + 0); return _inv_fail($e) if $e;
    my ($p, $pe) = dyn_profiles_all(); return _inv_fail($pe) if $pe;
    my ($old) = import_update_from($id + 0);   # a hint only: its absence is not an error
    return API::Response->ok({ dynamic => $z, profiles => $p, ($old ? (imported => $old) : ()) });
}
# PUT /zones/:id/dynamic: save the zone's dynamic update settings (see zone_dynamic_save).
sub _zone_dynamic {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($b, $bad) = _strict_body([qw(enabled profile_id cidrs key save_as_profile)]); return $bad if $bad;
    my ($r, $e) = zone_dynamic_save($id + 0, $b); return _inv_fail($e) if $e;
    _dyn_key_audit($u, $r->{key_change}, "dynamic updates of $zone->{name}");
    _inv_audit($u, 'dyn_profile_create', 'dyn_profile', $r->{created_profile}{id},
               { label => $r->{created_profile}{name}, after => { name => $r->{created_profile}{name}, from_zone => $zone->{name} } })
        if $r->{created_profile};
    _inv_audit($u, 'zone_dynamic_set', 'zone', $zone->{name},
               { after => { enabled => $r->{enabled}, mode => $r->{mode}, profile => $r->{profile}, cidrs => $r->{cidrs},
                            key => ($r->{key} ? $r->{key}{name} : undef) } });
    return API::Response->ok($r);
}

# DNSSEC of a primary zone (see zone_dnssec_*). GET the keys; PUT {enabled, algorithm?} signs with one new CSK
# or removes every key; keys are added (generated or imported from a BIND .private), switched and deleted.
sub _zone_dnssec_get {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($r, $e) = zone_dnssec_get($id + 0); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}
sub _zone_dnssec_set {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($b, $bad) = _strict_body([qw(enabled algorithm)]); return $bad if $bad;
    my ($r, $e) = zone_dnssec_set($id + 0, ($b->{enabled} ? 1 : 0), $b->{algorithm}); return _inv_fail($e) if $e;
    _inv_audit($u, ($b->{enabled} ? 'zone_dnssec_enable' : 'zone_dnssec_disable'), 'zone', $zone->{name},
               { after => { signed => ($b->{enabled} ? 1 : 0) } }) unless $r->{unchanged};
    return API::Response->ok($r);
}
sub _zone_dnssec_key_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($b, $bad) = _strict_body([qw(keytype algorithm bits active privatekey)]); return $bad if $bad;
    my ($r, $e) = zone_dnssec_key_add($id + 0, $b); return _inv_fail($e) if $e;
    _inv_audit($u, 'zone_dnssec_key_add', 'zone', $zone->{name},
               { after => { key_id => $r->{key_id}, keytype => lc($b->{keytype} // 'csk'),
                            ($b->{privatekey} ? (imported => 1) : (algorithm => $b->{algorithm})) } });
    return API::Response->ok($r);
}
sub _zone_dnssec_key_set {
    my ($self, $id, $kid) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($b, $bad) = _strict_body([qw(active published)]); return $bad if $bad;
    my ($r, $e) = zone_dnssec_key_set($id + 0, $kid, $b); return _inv_fail($e) if $e;
    _inv_audit($u, 'zone_dnssec_key_set', 'zone', $zone->{name}, { after => { key_id => $kid + 0, %$b } });
    return API::Response->ok($r);
}
sub _zone_dnssec_key_delete {
    my ($self, $id, $kid) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($r, $e) = zone_dnssec_key_delete($id + 0, $kid); return _inv_fail($e) if $e;
    _inv_audit($u, 'zone_dnssec_key_delete', 'zone', $zone->{name}, { before => { key_id => $kid + 0 } });
    return API::Response->ok($r);
}

# DNSSEC of a signed zone in the import list: GET what it signs with and which key files are loaded;
# POST keys {keys: [{name, content}]} adds its BIND key files; PUT {unsigned} imports it without DNSSEC.
sub _import_zone_dnssec {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($r, $e) = import_zone_dnssec($id); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}
sub _import_zone_dnssec_keys {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(keys)]); return $bad if $bad;
    my ($r, $e) = import_zone_dnssec_keys($id, $b->{keys}); return API::Response->bad_request($e) if $e;
    _inv_audit($u, 'import_dnssec_keys', 'zone', $r->{zone}, { after => { keys => [ map { $_->{tag} } grep { $_->{have} } @{ $r->{keys} } ] } });
    return API::Response->ok($r);
}
sub _import_zone_dnssec_unsigned {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(unsigned)]); return $bad if $bad;
    my ($r, $e) = import_zone_dnssec_unsigned($id, $b->{unsigned} ? 1 : 0); return _inv_fail($e) if $e;
    _inv_audit($u, 'import_dnssec_unsigned', 'zone', $r->{zone}, { after => { unsigned => $r->{unsigned} } });
    return API::Response->ok($r);
}
# POST /import/sources/:id/probe {zones?, tsig?}: queue the source's zones for probing (SOA serial, record count);
# the worker probes in batches. GET /import/zones/:id/diff?tsig=: old server vs our zone per RRset (display only).
# tsig is the PowerDNS key name used to sign AXFR from the old server (the one chosen for migration).
sub _import_probe {
    my ($self, $sid) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(zones tsig)]); return $bad if $bad;
    my ($r, $e) = import_probe_queue($sid, $b->{zones}, $b->{tsig}); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}
# POST /import/zones/:id/take {confirm_name, tsig?}: "Use old server version". A zone already in the panel
# becomes what migration would make it (Secondary of the old server); our records are replaced. Name
# confirmation, and distribution.manage for a catalog zone, as with Make secondary, which this is.
sub _import_take {
    my ($self, $id) = @_; my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(confirm_name tsig)]); return $bad if $bad;
    my $dbh = functions::connectDB() or return API::Response->service_unavailable('Database unavailable');
    my ($zn) = $dbh->selectrow_array("SELECT zone_name FROM import_zones WHERE id=?", undef, $id);
    return API::Response->not_found('not found') unless defined $zn;
    return API::Response->bad_request('confirm_name must match the zone name') unless lc($b->{confirm_name} // '') eq lc($zn);
    my $zone = pdns_get_domain_by_name($zn);
    if ($zone && zone_catalog_of($dbh, $zone->{id})) {
        return API::Response->forbidden("Capability 'distribution.manage' required to take the zone out of its catalog")
            unless has_capability($user, 'distribution.manage');
    }
    my ($r, $e) = import_zone_take($id, { tsig => $b->{tsig} }); return _inv_fail($e) if $e;
    _inv_audit($user, 'zone_import_take', 'zone', $r->{id},
               { before => { type => $r->{was} }, after => { type => 'SLAVE', masters => $r->{masters}, tsig => $r->{tsig} },
                 detail => 'replaced by the import version' });
    my %out = (%$r, catalog_removed => ($r->{catalog_removed} ? JSON::true : JSON::false));
    _tsig_sweep($user, \%out, $r->{tsig_released}) if $r->{tsig_released};
    return API::Response->ok(\%out);
}
# POST /import/zones/:id/copy {rrsets:[{name,type}], tsig?}: Copy from Compare - selected source RRsets into
# the panel zone. Same rights and write path as record editing (PATCH /zones/:id/rrsets): write on the zone,
# one transaction, replace_rrset audit per set, same purge/verify/notify post-path.
sub _import_copy {
    my ($self, $id) = @_;
    # Rights are checked BEFORE contacting the source: without them there is no reason to AXFR a foreign server.
    my ($user, $deny) = $self->_zones_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(rrsets tsig)]); return $bad if $bad;
    my $dbh = functions::connectDB() or return API::Response->service_unavailable('Database unavailable');
    my ($zn) = $dbh->selectrow_array("SELECT zone_name FROM import_zones WHERE id=?", undef, $id);
    return API::Response->not_found('not found') unless defined $zn;
    my $zone = pdns_get_domain_by_name($zn) or return API::Response->not_found('the zone is not in the panel — import it as usual');
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';
    my ($c, $e) = import_zone_copy_ops($id, $b->{rrsets}, $b->{tsig}); return _inv_fail($e) if $e;
    my $all_before = pdns_list_rrsets($c->{zone_id});
    my ($ok, $err, $serial) = pdns_apply_rrsets($c->{zone_id}, $c->{ops}, $user->{username});
    for my $op (@{ $c->{ops} }) {
        my ($before) = grep { lc($_->{name}) eq lc($op->{name}) && uc($_->{type}) eq $op->{type} } @$all_before;
        audit_log({ actor => $user->{username}, source => 'api', action => 'replace_rrset',
                    target_type => 'rrset', target => "$op->{name} $op->{type}",
                    before => $before, after => { ttl => $op->{ttl}, records => $op->{records} },
                    result => ($ok ? 'ok' : 'error'), detail => ($ok ? 'copied from import' : $err), ip => get_client_ip() });
    }
    return API::Response->bad_request($err) unless $ok;
    my $sync = _post_write_sync($zone->{name}, $serial);
    return API::Response->ok({ zone => $zone->{name}, applied => scalar(@{ $c->{ops} }), sync => _sync_payload($sync) });
}
sub _import_diff {
    my ($self, $id) = @_; my ($u, $deny) = $self->_zones_ok; return $deny if $deny;
    my $q = $self->{cgi};
    my ($r, $e) = import_zone_diff($id, $q ? scalar $q->param('tsig') : undef); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}

# POST /zones/:id/refresh-axfr: ask PowerDNS to re-fetch the zone from its primary (always retrieve, unlike
# Retry now). Same rights as Retry: zone settings don't change. The answer is "AXFR requested", not
# "arrived": arrival shows in Last check, which the worker also watches.
sub _refresh_axfr {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';
    return API::Response->bad_request('Only a secondary zone is transferred from a primary')
        unless uc($zone->{type} // '') eq 'SLAVE';

    my @masters = grep { length } split /\s*,\s*/, ($zone->{master} // '');
    my $res = zone_secondary_refresh($zone->{name});
    audit_log({ actor => $user->{username}, source => 'panel', ip => get_client_ip(),
                action => 'refresh_axfr', target_type => 'zone', target => $zone->{name},
                after => { masters => \@masters, pdns_state => $res->{pdns_state} },
                result => ($res->{requested} ? 'ok' : 'error'),
                detail => ($res->{requested} ? 'AXFR requested' . ($res->{error} ? "; $res->{error}" : '') : $res->{error}) });
    return API::Response->server_error($res->{error}) unless $res->{requested};
    return API::Response->ok({ zone => $zone->{name}, masters => \@masters, pdns_state => $res->{pdns_state},
        ($res->{error} ? (warnings => [ "the transfer was requested, but its state was not saved: $res->{error}" ]) : ()) });
}

# PATCH /zones/:id/rrsets: apply a set of RRset changes.
# body: { rrsets: [ { name, type, ttl?, changetype: "REPLACE"|"DELETE",
#                     records: [ {content, prio?, disabled?} ] } ] }
#
# _post_write_sync is the single post-commit path for ALL write paths (API/UI/MCP): purge -> verify(serial) ->
# [rediscover -> purge -> verify] -> notify. The durable state is ALWAYS written from the real verify.
# $serial is the SOA serial expected after the edit, to check PowerDNS really serves the fresh zone.
sub _post_write_sync {
    my ($zone_name, $serial) = @_;
    my $v = zone_sync_verify($zone_name, $serial);
    my $sok = set_zone_sync_state($zone_name, $v->{pdns_state}, $v->{notify_state}, $v->{detail});
    $v->{state_error} = 1 unless $sok;   # durable state not written -> auto-retry NOT scheduled
    return $v;
}
# API sync block from the split states (JSON-safe).
sub _sync_payload {
    my ($v) = @_;
    return { pdns_state => $v->{pdns_state}, notify_state => $v->{notify_state},
             detail => $v->{detail},
             ($v->{state_error} ? (state_error => JSON::true) : ()) };
}

sub _patch_rrsets {
    my ($self, $zone_id) = @_;
    my $zone = pdns_get_domain($zone_id) or return API::Response->not_found('Zone not found');

    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';
    return API::Response->forbidden("Zone '$zone->{name}' is SLAVE (read-only; data arrives via AXFR)")
        if uc($zone->{type} || '') eq 'SLAVE';

    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $rrsets = $body->{rrsets};
    return API::Response->bad_request('rrsets[] is required')
        unless ref($rrsets) eq 'ARRAY' && @$rrsets;

    # changetype is NOT defaulted: the core (_canonicalize_ops) does the strict check (REPLACE|DELETE,
    # duplicates, empty REPLACE).
    my @ops;
    for my $rr (@$rrsets) {
        my $type = uc($rr->{type} // '');
        my $ct   = uc($rr->{changetype} // '');
        push @ops, {
            name       => _fqdn($rr->{name}, $zone->{name}),
            type       => $type,
            ttl        => $rr->{ttl},
            changetype => $rr->{changetype},   # as sent; the core rejects empty/unknown
            records    => ($ct eq 'DELETE' ? [] : _normalize_records($type, $rr->{records})),
        };
    }

    # "before" snapshots for audit.
    my $all_before = pdns_list_rrsets($zone_id);
    my %before;
    for my $op (@ops) {
        ($before{"$op->{name}\0$op->{type}"}) =
            grep { lc($_->{name}) eq lc($op->{name}) && uc($_->{type}) eq $op->{type} } @$all_before;
    }

    # ATOMIC: one transaction, one SOA bump, all or nothing. actor -> records.updated_by/at.
    my ($ok, $err, $serial) = pdns_apply_rrsets($zone_id, \@ops, $user->{username});

    for my $op (@ops) {
        my $is_del = uc($op->{changetype} // '') eq 'DELETE';
        audit_log({
            actor => $user->{username}, source => 'api',
            action => ($is_del ? 'delete_rrset' : 'replace_rrset'),
            target_type => 'rrset', target => "$op->{name} $op->{type}",
            before => $before{"$op->{name}\0$op->{type}"},
            after  => ($is_del ? undef : { ttl => $op->{ttl}, records => $op->{records} }),
            result => ($ok ? 'ok' : 'error'), detail => $err,
            ip => get_client_ip(), request_id => $body->{request_id},
        });
    }

    return API::Response->bad_request($err) unless $ok;   # atomic: the whole PATCH was not applied

    my $sync = _post_write_sync($zone->{name}, $serial);
    return API::Response->ok({ zone => $zone->{name}, applied => scalar(@ops),
                              sync => _sync_payload($sync) });
}

# PATCH /zones/:id/soa: dedicated SOA editor (SOA is blocked in the generic rrset path).
# body: {primary_ns,hostmaster,serial?,refresh,retry,expire,minimum,ttl}. Requires write.
sub _patch_soa {
    my ($self, $zone_id) = @_;
    my $zone = pdns_get_domain($zone_id) or return API::Response->not_found('Zone not found');
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';
    return API::Response->forbidden("Zone '$zone->{name}' is SLAVE (read-only; data arrives via AXFR)")
        if uc($zone->{type} || '') eq 'SLAVE';

    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $before = pdns_soa_fields($zone_id);
    my %f;   # only fields actually sent, or an undef key would falsely trigger 'required'
    for my $k (qw(primary_ns hostmaster serial refresh retry expire minimum ttl)) {
        $f{$k} = $body->{$k} if defined $body->{$k};
    }
    my ($ok, $after) = pdns_update_soa($zone_id, \%f, $user->{username});
    return API::Response->bad_request($after) unless $ok;   # on failure $after is the error message

    my $sync = _post_write_sync($zone->{name}, $after->{serial});   # verify(serial) + durable
    my $now  = pdns_soa_fields($zone_id);
    # Audited as an RRset ("<zone> SOA") shaped {ttl,records:[{content}]}, so SOA history renders in the same
    # table as ordinary records (GET /zones/:id/audit?type=SOA).
    my $soa_content = sub { my $s = shift; join(' ', map { $s->{$_} } qw(primary_ns hostmaster serial refresh retry expire minimum)); };
    audit_log({
        actor => $user->{username}, source => 'api',
        action => 'update_soa', target_type => 'rrset', target => "$zone->{name} SOA",
        before => { ttl => ($before ? $before->{ttl} : undef), records => [ { content => ($before ? $soa_content->($before) : '') } ] },
        after  => { ttl => ($now ? $now->{ttl} : undef),       records => [ { content => $soa_content->($now) } ] },
        result => 'ok', ip => get_client_ip(), request_id => $body->{request_id},
    });
    return API::Response->ok({ zone => $zone->{name}, soa => pdns_soa_fields($zone_id),
                              sync => _sync_payload($sync) });
}

# --- Apex NS: per-row CRUD (each NS is its own records row with its own updated_by/at) ---
# TTL belongs to the whole RRset. Audited as rrset "<zone> NS" (one history).
sub _ns_check_write {
    my ($self, $id) = @_;
    my $zone = pdns_get_domain($id) or return (undef, API::Response->not_found('Zone not found'));
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    return (undef, API::Response->forbidden("No write access to zone '$zone->{name}'"))
        unless effective_zone_access($user, $zone) eq 'write';
    # Manual edits only for authoritative zones: SLAVE content comes from AXFR.
    return (undef, API::Response->forbidden("Zone '$zone->{name}' is SLAVE (read-only; data arrives via AXFR)"))
        if uc($zone->{type} || '') eq 'SLAVE';
    return ($zone, $user);
}
sub _ns_apply_result {
    my ($self, $zone, $user, $info, $body) = @_;
    my $sync = _post_write_sync($zone->{name}, $info->{serial});   # verify(serial) + durable
    my $wrap = sub { my $c = shift; defined $c ? { ttl => $info->{ttl}, records => [ { content => $c } ] } : undef; };
    my %amap = (add => 'add_ns', update => 'update_ns', delete => 'delete_ns');
    audit_log({
        actor => $user->{username}, source => 'api',
        action => ($amap{ $info->{action} } || 'update_ns'),
        target_type => 'rrset', target => "$zone->{name} NS",
        before => $wrap->($info->{before}), after => $wrap->($info->{after}),
        result => 'ok', ip => get_client_ip(), request_id => $body->{request_id},
    });
    return API::Response->ok({ zone => $zone->{name},
        name_servers => pdns_apex_ns_list($zone->{id}, $zone->{name}),
        sync => _sync_payload($sync) });
}
# POST /zones/:id/name-servers — body {content, ttl?}
sub _ns_add {
    my ($self, $id) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;   # on error $user is the Response
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $content = $body->{content};
    return API::Response->bad_request('content is required') unless defined $content && length $content;
    my $ttl = (defined $body->{ttl} && $body->{ttl} =~ /^\d+$/) ? $body->{ttl} : 3600;
    if (my $e = dns_validate('NS', $zone->{name}, $ttl, $content, undef)) { return API::Response->bad_request($e); }
    my ($ok, $info) = pdns_apex_ns_mutate($id, $zone->{name},
        { action => 'add', content => $content, ttl => $body->{ttl}, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _ns_apply_result($self, $zone, $user, $info, $body);
}
# PATCH /zones/:id/name-servers/:record_id — body {content?, ttl?}
sub _ns_update {
    my ($self, $id, $rid) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    if (defined $body->{content} && length $body->{content}) {
        my $ttl = (defined $body->{ttl} && $body->{ttl} =~ /^\d+$/) ? $body->{ttl} : 3600;
        if (my $e = dns_validate('NS', $zone->{name}, $ttl, $body->{content}, undef)) { return API::Response->bad_request($e); }
    }
    my ($ok, $info) = pdns_apex_ns_mutate($id, $zone->{name},
        { action => 'update', record_id => $rid, content => $body->{content}, ttl => $body->{ttl}, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _ns_apply_result($self, $zone, $user, $info, $body);
}
# DELETE /zones/:id/name-servers/:record_id
sub _ns_delete {
    my ($self, $id, $rid) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() || {};
    my ($ok, $info) = pdns_apex_ns_mutate($id, $zone->{name},
        { action => 'delete', record_id => $rid, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _ns_apply_result($self, $zone, $user, $info, $body);
}

# --- Ordinary records: per-row CRUD (UI model "one record = one row") ---
# RRset integrity (CNAME, single TTL, duplicates, one SOA bump) is enforced in pdns_record_mutate.
# Audited as rrset "<fqdn> <TYPE>" (add_record/update_record/delete_record), giving each record its history.
sub _record_apply_result {
    my ($self, $zone, $user, $info, $body) = @_;
    my $sync = _post_write_sync($zone->{name}, $info->{serial});   # verify(serial) + durable
    my $wrap = sub {
        my ($content, $dis) = @_;
        return undef unless defined $content;
        return { ttl => $info->{ttl}, records => [ { content => $content, disabled => ($dis ? 1 : 0) } ] };
    };
    my %amap = (add => 'add_record', update => 'update_record', delete => 'delete_record');
    my ($before, $after);
    if ($info->{action} eq 'add')      { $before = undef;                                   $after = $wrap->($info->{after},  $info->{after_dis}); }
    elsif ($info->{action} eq 'update'){ $before = $wrap->($info->{before}, $info->{before_dis}); $after = $wrap->($info->{after}, $info->{after_dis}); }
    else                               { $before = $wrap->($info->{before}, 0);              $after = undef; }
    audit_log({
        actor => $user->{username}, source => 'api',
        action => ($amap{ $info->{action} } || 'update_record'),
        target_type => 'rrset', target => "$info->{name} $info->{type}",
        before => $before, after => $after,
        result => 'ok', ip => get_client_ip(), request_id => $body->{request_id},
    });
    return API::Response->ok({ zone => $zone->{name}, name => $info->{name}, type => $info->{type},
        sync => _sync_payload($sync) });
}
# POST /zones/:id/records — body {name, type, content, ttl?, prio?, disabled?}
sub _record_add {
    my ($self, $id) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $type = uc($body->{type} // '');
    my $content = $body->{content};
    return API::Response->bad_request('name, type and content are required')
        unless length $type && defined $content && length $content && defined $body->{name};
    my $fqdn = _fqdn($body->{name}, $zone->{name});
    my ($ok, $info) = pdns_record_mutate($id, { action => 'add', name => $fqdn, type => $type,
        content => $content, ttl => $body->{ttl}, prio => $body->{prio}, disabled => $body->{disabled}, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _record_apply_result($self, $zone, $user, $info, $body);
}
# POST /zones/:id/records/with-ptr: atomic A + PTR. body: {name,type,content,ttl?,ptr_mode?}.
# ptr_mode: 'auto' | 'a_only' | 'replace'. The free/conflict/replace decision is made INSIDE the transaction
# under lock (pdns_create_address_ptr), so there is no race. not_managed is decided here (not racy).
# Response: {blocked:true, reason, request_id, ...} (nothing created) or success {a,ptr,sync,...}.
sub _record_add_with_ptr {
    my ($self, $id) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    # Forward zones only; otherwise fwd/rev could coincide (double bump, logical confusion).
    return API::Response->bad_request('A + PTR is available on forward zones only')
        if zone_kind($zone->{name}) =~ /^reverse/;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');

    # 1) Validate BEFORE the reverse lookup: type, name, content, ttl, ptr_mode whitelist.
    my $type = uc($body->{type} // '');
    my $ip   = $body->{content};
    return API::Response->bad_request('PTR creation is supported for A/AAAA records only')
        unless $type eq 'A' || $type eq 'AAAA';
    return API::Response->bad_request('name and content are required')
        unless defined $body->{name} && defined $ip && length $ip;
    my $mode = $body->{ptr_mode} // 'auto';
    return API::Response->bad_request("invalid ptr_mode '$mode'") unless $mode =~ /^(auto|a_only|replace)$/;
    return API::Response->bad_request('ttl must be a number')
        if defined $body->{ttl} && $body->{ttl} ne '' && $body->{ttl} !~ /^\d+$/;
    my $fqdn = _fqdn($body->{name}, $zone->{name});
    if (my $e = dns_validate($type, $fqdn, ($body->{ttl} // 3600), $ip, undef)) { return API::Response->bad_request($e); }
    my $target = $fqdn . '.';

    # request_id is shared by A and PTR (generated if the client sent none) and returned. It is a
    # CORRELATION id (links A<->PTR in audit), NOT idempotency. Capped at 64 chars (column size).
    my $rid = $body->{request_id};
    unless (defined $rid && length $rid) { $rid = sprintf('r3-%d-%06d', time(), int(rand(1_000_000))); }
    $rid = substr($rid, 0, 64);

    my ($owner) = reverse_candidates_for_ip($ip);            # owner for display, even without a zone

    # 2) Local reverse zone + writability. reverse_zone is revealed ONLY with access (read/write), otherwise
    #    the zone's existence stays hidden (none = unknown external).
    my ($rev, $rev_err) = reverse_master_for_ip($ip);
    return API::Response->bad_request("reverse lookup failed: $rev_err") if $rev_err;   # fail-closed
    my ($rev_access, $rev_writable, $rev_visible) = ('none', 0, undef);
    if ($rev) {
        my $rd = pdns_get_domain($rev->{domain_id});
        $rev_access = $rd ? $self->_access($rd) : 'none';
        $rev_writable = ($rd && ($rev->{type} eq 'MASTER' || $rev->{type} eq 'NATIVE') && $rev_access eq 'write') ? 1 : 0;
        $rev_visible  = ($rev_access ne 'none') ? $rev->{zone_name} : undef;
    }

    # 3) Not managed here (no zone / SLAVE / no rights / external DNS): not racy, decided here.
    if (!$rev_writable && $mode ne 'a_only') {
        return API::Response->ok({ blocked => JSON::true, reason => 'not_managed',
            ip => $ip, owner => $owner, target => $target, reverse_zone => $rev_visible, request_id => $rid });
    }

    # 4) Atomic (the PTR decision is made under lock inside). a_only -> no PTR written.
    my ($out, $err) = pdns_create_address_ptr({
        fwd_id => $id, fwd_name => $fqdn, a_type => $type, ip => $ip, ttl => $body->{ttl},
        rev_id => ($rev_writable ? $rev->{domain_id} : undef),
        owner  => ($rev_writable ? $rev->{owner} : undef),
        target => $target, ptr_mode => $mode, actor => $user->{username},
    });
    return API::Response->bad_request($err) unless $out;

    # Blocked under lock (conflict/disabled in auto): nothing created.
    if ($out->{blocked}) {
        return API::Response->ok({ blocked => JSON::true, reason => 'conflict', status => $out->{status},
            existing => ($out->{existing} || []), ip => $ip, owner => $owner, target => $target,
            reverse_zone => $rev_visible, request_id => $rid });
    }

    # 5) Confirmed post-write path: purge -> verify(serial) -> [rediscover -> purge -> verify] -> notify.
    # The durable state is ALWAYS written from the real verify (active = PowerDNS serves the expected serial).
    $ip = $out->{ip};                 # canonicalised address (for audit/response)
    my $eff_ttl = $out->{eff_ttl};
    my $ptr_written = ($out->{ptr} eq 'created' || $out->{ptr} eq 'replaced') ? 1 : 0;
    my $vf = _post_write_sync($zone->{name}, $out->{fwd_serial});
    my $vr;
    if ($ptr_written) {
        $vr = _post_write_sync($rev->{zone_name}, $out->{rev_serial});
    }

    audit_log({ actor => $user->{username}, source => 'api',
        action => 'add_record', target_type => 'rrset', target => "$fqdn $type",
        before => undef, after => { ttl => $eff_ttl, records => [ { content => $ip } ] },
        result => 'ok', ip => get_client_ip(), request_id => $rid });
    if ($ptr_written) {
        audit_log({ actor => $user->{username}, source => 'api',
            action => ($out->{ptr} eq 'replaced' ? 'replace_rrset' : 'add_record'),
            target_type => 'rrset', target => "$rev->{owner} PTR",
            before => (@{ $out->{replaced} || [] } ? { records => [ map { { content => $_ } } @{ $out->{replaced} } ] } : undef),
            after  => { ttl => $eff_ttl, records => [ { content => $target } ] },
            result => 'ok', ip => get_client_ip(), request_id => $rid });
    }
    return API::Response->created({ address => 'created', type => $type, ptr => $out->{ptr}, ttl => $eff_ttl,
        request_id => $rid, reverse_zone => $rev_visible, owner => $owner,
        sync => { forward => _sync_payload($vf),
                  reverse => ($ptr_written ? _sync_payload($vr) : undef) } });
}

# POST /zones/:fwd_id/records/:record_id/ptr: create a PTR for an existing A/AAAA (Missing -> "+").
# IP/type/target come FROM the record (the frontend does not send target); body: { mode?: 'auto'|'replace' }.
# The PTR is rechecked under lock in the core (the table status is not trusted). Rights: access to the forward
# zone (to see the record) + WRITE on the reverse zone. blocked (conflict/disabled/not_managed) -> nothing created.
sub _record_create_ptr {
    my ($self, $zone_id, $record_id) = @_;
    my $zone = pdns_get_domain($zone_id) or return API::Response->not_found('Zone not found');
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->not_found('Zone not found') if $self->_access($zone) eq 'none';

    my $pf = ptr_reverse_for_record($zone_id, $record_id);
    if ($pf->{error}) {
        return API::Response->not_found('Record not found') if $pf->{error} eq 'record not found';
        return API::Response->bad_request($pf->{error});
    }
    return API::Response->ok({ blocked => JSON::true, reason => $pf->{reason}, status => 'external' })
        if $pf->{blocked};                                  # no local reverse zone -> external
    return API::Response->forbidden('No write access to the reverse zone')
        unless access_for($self->_ctx, $pf->{rev_id}) eq 'write';

    my $body = _json_body() || {};
    my $mode = (defined $body->{mode} && $body->{mode} eq 'replace') ? 'replace' : 'auto';

    my ($out, $err) = pdns_create_record_ptr($zone_id, $record_id, $mode, $user->{username});
    return API::Response->bad_request($err) if $err;

    if ($out->{blocked}) {                                  # conflict/disabled(auto)/not_writable: nothing created
        return API::Response->ok({ blocked => JSON::true, reason => $out->{reason}, status => $out->{status},
            existing => ($out->{existing} || []),
            reverse_zone_id => $out->{rev_id}, owner => $out->{owner} });
    }

    my $sync;
    if ($out->{ptr} ne 'exists' && $out->{serial}) {        # actually written -> verified sync + audit
        my $v = _post_write_sync($out->{rev_name}, $out->{serial});
        $sync = _sync_payload($v);
        my $rid = sprintf('r4-%d-%06d', time(), int(rand(1_000_000)));
        audit_log({ actor => $user->{username}, source => 'api',
            action => ($out->{ptr} eq 'replaced' ? 'replace_rrset' : 'add_record'),
            target_type => 'rrset', target => "$out->{owner} PTR",
            before => (@{ $out->{replaced} || [] } ? { records => [ map { { content => $_ } } @{ $out->{replaced} } ] } : undef),
            after  => { ttl => $out->{ttl}, records => [ { content => $out->{target} } ] },
            result => 'ok', ip => get_client_ip(), request_id => $rid });
    }
    return API::Response->ok({ ptr => $out->{ptr}, status => 'ok',
        reverse_zone_id => $out->{rev_id}, owner => $out->{owner}, target => $out->{target},
        ttl => $out->{ttl}, ($sync ? (sync => $sync) : ()) });
}

# PATCH /zones/:id/records/:record_id: body {content?, ttl?, prio?, disabled?}
sub _record_update {
    my ($self, $id, $rid) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my ($ok, $info) = pdns_record_mutate($id, { action => 'update', record_id => $rid,
        content => $body->{content}, ttl => $body->{ttl}, prio => $body->{prio}, disabled => $body->{disabled}, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _record_apply_result($self, $zone, $user, $info, $body);
}
# DELETE /zones/:id/records/:record_id
sub _record_delete {
    my ($self, $id, $rid) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() || {};
    my ($ok, $info) = pdns_record_mutate($id, { action => 'delete', record_id => $rid, actor => $user->{username} });
    return API::Response->bad_request($info) unless $ok;
    return _record_apply_result($self, $zone, $user, $info, $body);
}

# POST /zones/:id/records/delete: the single record deletion path (single AND bulk) with optional matching
# PTRs. body: { ids:[...], ptr_ids:[...] } (ptr_ids is a subset of ids: those whose PTR is deleted too).
# ONE transaction across all affected zones (forward + reverse), one bump and verified sync per zone.
# A PTR is deleted only for A/AAAA + local MASTER/NATIVE reverse zone + WRITE access + exact match
# content == record FQDN (rechecked under lock in the core). No rights/zone -> PTR left alone.
sub _records_delete {
    my ($self, $id) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $ids = $body->{ids};
    return API::Response->bad_request('ids[] is required') unless ref($ids) eq 'ARRAY' && @$ids;
    my @nids = grep { defined && /^\d+$/ } @$ids;
    return API::Response->bad_request('no valid record ids') unless @nids;
    my %want_ptr = map { $_ => 1 } grep { defined && /^\d+$/ } @{ $body->{ptr_ids} || [] };

    # PTR target preflight: local writable reverse zone + WRITE access, otherwise the PTR is left alone.
    my (@items, %rev_names);
    for my $rid (@nids) {
        my $it = { record_id => $rid };
        if ($want_ptr{$rid}) {
            my $pf = ptr_reverse_for_record($id, $rid);
            # Fail closed: a preflight error (including a reverse read error) must NOT silently become
            # "delete only the A". Abort; the user sees fresh state and retries.
            return API::Response->bad_request("PTR preflight failed for record $rid: $pf->{error}") if $pf->{error};
            if ($pf->{ok} && ($pf->{rev_type} eq 'MASTER' || $pf->{rev_type} eq 'NATIVE')
                && access_for($self->_ctx, $pf->{rev_id}) eq 'write') {
                $it->{ptr} = { rev_id => $pf->{rev_id}, owner => $pf->{owner}, target => $pf->{target},
                               exp_ip => $pf->{ip} };   # exp_ip: concurrent recheck under lock in the core
                $rev_names{ $pf->{rev_id} } = $pf->{rev_name};
            }
        }
        push @items, $it;
    }

    my ($out, $err) = pdns_delete_records_ptr($id, \@items, $user->{username});
    return API::Response->bad_request($err) unless $out;

    my $corr = sprintf('r4-%d-%06d', time(), int(rand(1_000_000)));   # links forward+reverse in audit
    my $vf = _post_write_sync($zone->{name}, $out->{fwd_serial});
    for my $r (@{ $out->{deleted} }) {
        audit_log({ actor => $user->{username}, source => 'api',
            action => 'delete_record', target_type => 'rrset', target => "$r->{name} $r->{type}",
            before => { ttl => $r->{ttl}, records => [ { content => $r->{content} } ] }, after => undef,
            result => 'ok', ip => get_client_ip(), request_id => $corr });
    }
    my %rev_sync;
    for my $rvid (keys %{ $out->{rev_serials} }) {
        my $name = $rev_names{$rvid} or next;
        $rev_sync{$rvid} = _sync_payload(_post_write_sync($name, $out->{rev_serials}{$rvid}));
    }
    for my $p (@{ $out->{ptr_deleted} }) {
        audit_log({ actor => $user->{username}, source => 'api',
            action => 'delete_record', target_type => 'rrset', target => "$p->{owner} PTR",
            before => { records => [ { content => $p->{content} } ] }, after => undef,
            result => 'ok', ip => get_client_ip(), request_id => $corr });
    }
    # For warnSync, a flat {forward,reverse}: reverse = the first problematic zone, else the first one.
    my $rev_warn;
    for my $s (values %rev_sync) {
        if ($s->{pdns_state} ne 'active' || ($s->{notify_state} || '') eq 'notify_failed') { $rev_warn = $s; last; }
    }
    $rev_warn //= (values %rev_sync)[0];
    return API::Response->ok({ zone => $zone->{name},
        deleted => scalar(@{ $out->{deleted} }), ptr_deleted => scalar(@{ $out->{ptr_deleted} }),
        ptr_skipped => scalar(@{ $out->{ptr_stale} || [] }),   # PTRs left alone: the record changed under lock
        sync => { forward => _sync_payload($vf), reverse => $rev_warn } });
}

# POST /zones/:id/records/batch: bulk enable|disable|delete. body: {ids:[...], action}.
# One transaction + one SOA bump + one purge/notify; per-record audit with a shared request_id.
sub _records_batch {
    my ($self, $id) = @_;
    my ($zone, $user) = _ns_check_write($self, $id);
    return $user unless $zone;
    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $action = $body->{action} // '';
    my ($res, $err) = pdns_records_batch($id, $body->{ids}, $action, $user->{username});
    return API::Response->bad_request($err) unless $res;

    my $sync = _post_write_sync($zone->{name}, $res->{serial});   # verify(serial) + durable
    my $rid  = $body->{request_id};
    for my $r (@{ $res->{records} }) {
        my ($before, $after, $act);
        if ($action eq 'delete') {
            $act = 'delete_record';
            $before = { records => [ { content => $r->{content}, disabled => $r->{before_dis} } ] };
            $after  = undef;
        } else {
            $act = 'update_record';
            my $newdis = ($action eq 'disable') ? 1 : 0;
            $before = { records => [ { content => $r->{content}, disabled => $r->{before_dis} } ] };
            $after  = { records => [ { content => $r->{content}, disabled => $newdis } ] };
        }
        audit_log({
            actor => $user->{username}, source => 'api',
            action => $act, target_type => 'rrset', target => "$r->{name} $r->{type}",
            before => $before, after => $after, result => 'ok', ip => get_client_ip(), request_id => $rid,
        });
    }
    return API::Response->ok({ zone => $zone->{name}, action => $action,
        affected => scalar(@{ $res->{records} }),
        sync => _sync_payload($sync) });
}

# PUT /zones/:id/labels: replace a zone's labels. body: {labels:[value_id,...]}. Requires write.
sub _put_zone_labels {
    my ($self, $zone_id) = @_;
    my $zone = pdns_get_domain($zone_id) or return API::Response->not_found('Zone not found');
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("No write access to zone '$zone->{name}'")
        unless effective_zone_access($user, $zone) eq 'write';
    # Labels are panel metadata in dns_panel, not PowerDNS records, so they are allowed on SLAVE too.

    my $body = _json_body() or return API::Response->bad_request('Invalid JSON body');
    my $before = zone_labels_get($zone_id);
    my ($ok, $err) = zone_labels_set($zone_id, $body->{labels}, $user->{username});
    return API::Response->bad_request($err) unless $ok;
    my $after = zone_labels_get($zone_id);
    audit_log({
        actor => $user->{username}, source => 'api',
        action => 'update_zone_labels', target_type => 'zone', target => $zone->{name},
        before => [ map { "$_->{category}:$_->{value}" } @$before ],
        after  => [ map { "$_->{category}:$_->{value}" } @$after ],
        result => 'ok', ip => get_client_ip(),
    });
    return API::Response->ok({ zone => $zone->{name}, labels => $after });
}

# RRset value normalisation: for MX/SRV take the priority from the start of the string.
sub _normalize_records {
    my ($type, $records) = @_;
    my @out;
    for my $r (@{ $records || [] }) {
        my $content = defined $r->{content} ? $r->{content} : '';
        $content =~ s/^\s+//; $content =~ s/\s+$//;
        my $prio = $r->{prio};
        if (($type eq 'MX' || $type eq 'SRV') && !defined $prio && $content =~ /^(\d+)\s+(.+)$/) {
            $prio = $1; $content = $2;   # "10 mail.host" -> prio=10, content="mail.host"
        }
        push @out, { content => $content, prio => $prio, disabled => ($r->{disabled} ? 1 : 0) };
    }
    return \@out;
}

# ============================================================================
# Secondary distribution inventory endpoints (docs/21 §9).
# Strict core -> HTTP mapping: validation -> 400, not found/unknown -> 404,
# already/in use/conflict/FK -> 409, 'DB error' -> 500, 'DB unavailable' -> 503.
# Field-level RBAC: TSIG/IP groups/bindings/axfr_auth_mode -> distribution.manage;
# nodes/groups/endpoints -> secondary.manage. Denied -> audit result=denied.
# Audit: canonical before/after, the insert result is checked; the TSIG secret NEVER.
# ============================================================================

# Capability denial audit (docs/15).
sub _audit_denied {
    my ($user, $cap) = @_;
    audit_log({ actor => ($user ? $user->{username} : 'anonymous'),
                source => 'api', action => 'inventory_access_denied', target_type => 'capability', target => $cap,
                detail => (($ENV{'REQUEST_METHOD'} // '').' '.($ENV{'PATH_INFO'} // '')),
                result => 'denied', ip => get_client_ip() });
}
# Capability check error -> HTTP: 'DB error' -> 500, 'DB unavailable' -> 503.
sub _cap_err {
    my ($cerr) = @_;
    return API::Response->server_error('Internal database error') if $cerr eq 'DB error';
    return API::Response->service_unavailable('Database unavailable');
}
# Authentication only (no specific capability), for the "401/403 before body parsing" order.
sub _auth_ok {
    my ($self) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    return ($user, undef);
}
# RBAC for a specific capability. A DB error in the check -> 503/500 (not 403); denial -> denied audit + 403.
sub _cap_ok {
    my ($self, $cap) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    my ($has, $cerr) = capability_check($user, $cap);
    return (undef, _cap_err($cerr)) if $cerr;
    unless ($has) { _audit_denied($user, $cap); return (undef, API::Response->forbidden("Capability '$cap' required")); }
    return ($user, undef);
}
# Reading the inventory requires either of the two manage capabilities.
sub _inv_read_ok {
    my ($self) = @_;
    my $user = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $user;
    for my $cap (qw(secondary.manage distribution.manage)) {
        my ($has, $cerr) = capability_check($user, $cap);
        return (undef, _cap_err($cerr)) if $cerr;
        return ($user, undef) if $has;
    }
    _audit_denied($user, 'secondary.manage|distribution.manage');
    return (undef, API::Response->forbidden("Capability 'secondary.manage' or 'distribution.manage' required"));
}
# Core error -> HTTP.
sub _inv_fail {
    my ($err) = @_;
    $err //= 'error';
    return API::Response->service_unavailable('Database unavailable') if $err eq 'DB unavailable';
    return API::Response->server_error('Internal database error')     if $err eq 'DB error';
    return API::Response->not_found($err) if $err eq 'not found' || $err =~ /^unknown /;
    # "Busy, retry" is a conflict, not a bad request: the client sent everything right, someone else was
    # changing the same row that second. 400 would invite fixing a request with nothing to fix.
    return API::Response->conflict($err)  if $err =~ /^busy/;
    return API::Response->conflict($err)  if $err =~ /already|in use|conflict|invalid reference|constraint/;
    return API::Response->bad_request($err);
}
# Strict body: reject unknown fields; for PATCH also reject empty/only-unknown bodies.
# Returns ($body, undef) | (undef, $response).
sub _strict_body {
    my ($allowed, %opt) = @_;
    my $b = _json_body();
    return (undef, API::Response->bad_request('Invalid JSON body')) unless $b;
    my %ok = map { $_ => 1 } @$allowed;
    my @bad = grep { !$ok{$_} } keys %$b;
    return (undef, API::Response->bad_request('Unknown field(s): '.join(', ', sort @bad))) if @bad;
    if ($opt{patch} && !grep { $ok{$_} } keys %$b) {
        return (undef, API::Response->bad_request('No known fields to update'));
    }
    return ($b, undef);
}
# Mutation audit: before/after, the insert result is checked (docs/15). Secrets are never passed.
sub _inv_audit {
    my ($user, $action, $target_type, $target, $x) = @_;
    $x ||= {};
    # target_label is a snapshot of the object's readable name (survives deletion). Priority: explicit
    # $x->{label} -> live lookup by id -> name from the before snapshot (for deletes).
    my $label = defined $x->{label} ? $x->{label} : audit_target_label($target_type, $target);
    $label = _label_from_snapshot($x->{before}) if !defined $label && ref $x->{before} eq 'HASH';
    my $ok = audit_log({ actor => $user->{username}, source => 'api',
                action => $action, target_type => $target_type, target => "$target",
                (defined $label ? (target_label => $label) : ()),
                (defined $x->{before} ? (before => $x->{before}) : ()),
                (defined $x->{after}  ? (after  => $x->{after})  : ()),
                (defined $x->{detail} ? (detail => $x->{detail}) : ()),
                result => 'ok', ip => get_client_ip() });
    warn "[audit] insert FAILED for $action $target_type/$target\n" unless $ok;
    return $ok;
}
# Object name snapshot BEFORE deletion (delete handlers); delegates to the shared resolver in functions.
sub _audit_label { return audit_target_label(@_); }
# Readable name from a before snapshot (delete fallback: the object is gone and its id no longer resolves).
sub _label_from_snapshot {
    my ($snap) = @_; return undef unless ref $snap eq 'HASH';
    for my $k (qw(name username display_name fqdn principal code zone title)) {
        return $snap->{$k} if defined $snap->{$k} && length "$snap->{$k}";
    }
    return undef;
}
# Typed entity snapshot for before/after: ($data, undef) | (undef, 'not found'|'DB error'|'DB unavailable').
# Secrets are excluded (TSIG: name/algorithm only). Errors are NOT swallowed.
sub _inv_snapshot {
    my ($type, $id) = @_;
    return tsig_key_meta($id)       if $type eq 'tsig_key';
    return ip_group_get($id)        if $type eq 'ip_group';
    return secondary_group_get($id) if $type eq 'secondary_group';
    return secondary_node_get($id)  if $type eq 'secondary_node';
    return catalog_get($id) if $type eq 'catalog';
    return (undef, 'not found');
}
# The before snapshot is mandatory BEFORE a mutation: (data, undef) | (undef, $http_response).
sub _snap_before {
    my ($type, $id) = @_;
    my ($d, $e) = _inv_snapshot($type, $id);
    return $e ? (undef, _inv_fail($e)) : ($d, undef);
}
# The after snapshot, taken after a successful mutation, doesn't block (the write is done) but doesn't swallow
# errors either: returns ($data, $detail_or_undef), and the error goes into the audit detail.
sub _snap_after {
    my ($type, $id) = @_;
    my ($d, $e) = _inv_snapshot($type, $id);
    return ($d, $e ? "after-snapshot unavailable: $e" : undef);
}

# ---- TSIG keys (distribution.manage): the secret NEVER goes into a response or audit ----
# Except reveal (base64): the operator must hand the secret to a remote secondary. A deliberate relaxation of
# "secret is write-only": requires distribution.manage and every reveal is audited.
sub _tsig_reveal {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($r, $err) = tsig_key_secret($id); return _inv_fail($err) if $err;
    _inv_audit($user, 'tsig_key_reveal', 'tsig_key', $id, {});
    return API::Response->ok({ id => $r->{id}, name => $r->{name}, algorithm => $r->{algorithm}, secret => $r->{secret} });
}

# ---- IP groups (distribution.manage) ----
sub _ipg_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($rows, $err) = ip_groups_all();
    return _inv_fail($err) if $err;
    return API::Response->ok({ ip_groups => $rows });
}
sub _ipg_get {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($g, $err) = ip_group_get($id);
    return _inv_fail($err) if $err;
    return API::Response->ok({ ip_group => $g });
}
sub _ipg_create {
    my ($self) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)]); return $bad if $bad;
    my ($id, $err) = ip_group_create($b->{name}, $b->{description});
    return _inv_fail($err) if $err;
    my ($after, $d) = _snap_after('ip_group', $id);
    _inv_audit($user, 'ip_group_create', 'ip_group', $id, { after => $after, detail => $d });
    return API::Response->created({ id => $id + 0 });
}
sub _ipg_update {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)], patch => 1); return $bad if $bad;
    my ($before, $bderr) = _snap_before('ip_group', $id); return $bderr if $bderr;
    my %patch = map { $_ => $b->{$_} } grep { exists $b->{$_} } qw(name description);
    my ($ok, $err) = ip_group_update($id, \%patch);
    return _inv_fail($err) if $err;
    my ($after, $d) = _snap_after('ip_group', $id);
    _inv_audit($user, 'ip_group_update', 'ip_group', $id, { before => $before, after => $after, detail => $d });
    return API::Response->ok({ updated => JSON::true, id => $id + 0 });
}
sub _ipg_delete {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($before, $bderr) = _snap_before('ip_group', $id); return $bderr if $bderr;
    my ($ok, $err) = ip_group_delete($id);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'ip_group_delete', 'ip_group', $id, { before => $before });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}
sub _ipg_member_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(cidr)]); return $bad if $bad;
    my ($mid, $err, $canon) = ip_group_member_add($id, $b->{cidr});
    return _inv_fail($err) if $err;
    _inv_audit($user, 'ip_group_member_add', 'ip_group', $id, { after => { member_id => $mid + 0, cidr => $canon } });
        # An AXFR authorisation input changed -> recompute the policy NOW. Otherwise TSIG-ALLOW-AXFR and
        # ALLOW-AXFR-FROM stayed stale until the worker ran, and PowerDNS refused the transfer the panel had
        # asked the secondary to make.
        my $perr = policy_refresh();
    my %out = ( id => $mid + 0, cidr => $canon );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->created(\%out);
}
sub _ipg_member_del {
    my ($self, $id, $mid) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($ok, $err) = ip_group_member_delete($id, $mid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'ip_group_member_delete', 'ip_group', $id, { before => { member_id => $mid + 0 } });
        # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
        my $perr = policy_refresh();
    my %out = ( deleted => JSON::true, id => $mid + 0 );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}

# ---- Secondary groups (secondary.manage) + axfr_auth_mode/bindings (distribution.manage) ----
sub _sg_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($rows, $err) = secondary_groups_all();
    return _inv_fail($err) if $err;
    return API::Response->ok({ groups => $rows });
}
sub _sg_get {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($g, $err) = secondary_group_get($id);
    return _inv_fail($err) if $err;
    return API::Response->ok({ group => $g });
}
sub _sg_create {
    my ($self) = @_;
    # Structural create needs secondary.manage (auth before body parsing); an explicit delivery policy
    # (axfr_auth_mode etc.) additionally needs distribution.manage.
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description axfr_auth_mode send_notify zone_axfr)]); return $bad if $bad;
    if (exists $b->{axfr_auth_mode} || exists $b->{send_notify} || exists $b->{zone_axfr}) { (undef, my $d2) = $self->_cap_ok('distribution.manage'); return $d2 if $d2; }
    my ($id, $err) = secondary_group_create($b->{name}, $b->{description}, $b->{axfr_auth_mode}, $b->{send_notify}, $b->{zone_axfr});
    return _inv_fail($err) if $err;
    my ($after, $d) = _snap_after('secondary_group', $id);   # canonical (trimmed/normalised), not from the body
    _inv_audit($user, 'secondary_group_create', 'secondary_group', $id, { after => $after, detail => $d });
    return API::Response->created({ id => $id + 0 });
}
sub _sg_update {
    my ($self, $id) = @_;
    # Authenticate BEFORE parsing the body, or an anonymous caller with bad JSON would get 400 instead of 401.
    my ($user, $adeny) = $self->_auth_ok; return $adeny if $adeny;
    my ($b, $bad) = _strict_body([qw(name description axfr_auth_mode send_notify zone_axfr prefixes)], patch => 1); return $bad if $bad;
    # Field-level RBAC: name/description -> secondary.manage; axfr_auth_mode/send_notify/zone_axfr/prefixes (delivery policy) -> distribution.manage.
    if (exists $b->{name} || exists $b->{description})   { (my $u, my $d) = $self->_cap_ok('secondary.manage');    return $d if $d; $user = $u; }
    if (exists $b->{axfr_auth_mode} || exists $b->{send_notify} || exists $b->{zone_axfr} || exists $b->{prefixes}) { (my $u, my $d) = $self->_cap_ok('distribution.manage'); return $d if $d; $user = $u; }
    my ($before, $bderr) = _snap_before('secondary_group', $id); return $bderr if $bderr;
    my %patch = map { $_ => $b->{$_} } grep { exists $b->{$_} } qw(name description axfr_auth_mode send_notify zone_axfr);
    my ($ok, $err) = %patch ? secondary_group_update($id, \%patch) : (1, undef);
    return _inv_fail($err) if $err;
    my $prefixes;
    if (exists $b->{prefixes}) { ($prefixes, $err) = secondary_group_prefixes_set($id, $b->{prefixes}); return _inv_fail($err) if $err; }
    my ($after, $d) = _snap_after('secondary_group', $id);
    _inv_audit($user, 'secondary_group_update', 'secondary_group', $id, { before => $before, after => $after, detail => $d });
    # All three are policy inputs: axfr_auth_mode switches the group between TSIG and IP ACL, i.e. changes
    # TSIG-ALLOW-AXFR/ALLOW-AXFR-FROM, so without a refresh PowerDNS kept the old mode until the worker ran.
    if (exists $b->{send_notify} || exists $b->{axfr_auth_mode} || exists $b->{zone_axfr} || exists $b->{prefixes}) {
        my $perr = policy_refresh();
        return API::Response->ok({ updated => JSON::true, id => $id + 0, ($prefixes ? (prefixes => $prefixes) : ()), policy_warning => join('; ', @$perr) }) if @$perr;
    }
    return API::Response->ok({ updated => JSON::true, id => $id + 0, ($prefixes ? (prefixes => $prefixes) : ()) });
}
sub _sg_delete {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($before, $bderr) = _snap_before('secondary_group', $id); return $bderr if $bderr;
    my ($ok, $err) = secondary_group_delete($id);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_delete', 'secondary_group', $id, { before => $before });
    my $perr = policy_refresh();
    my %out = ( deleted => JSON::true, id => $id + 0 );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}
sub _sg_member_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(node_id)]); return $bad if $bad;
    my ($ok, $err) = secondary_group_member_add($id, $b->{node_id});
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_member_add', 'secondary_group', $id, { after => { node_id => ($b->{node_id} // '')+0 } });
    # Return the refresh error to the operator: a silently swallowed warning hides the policy drift until
    # the worker runs.
    my $perr = policy_refresh();
    my %out = ( added => JSON::true, group_id => $id + 0, node_id => ($b->{node_id} // '')+0 );
    $out{policy_warning} = join('; ', @$perr) if $perr && @$perr;
    return API::Response->ok(\%out);
}
sub _sg_member_del {
    my ($self, $id, $nid) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($ok, $err) = secondary_group_member_remove($id, $nid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_member_remove', 'secondary_group', $id, { before => { node_id => $nid + 0 } });
    # Return the refresh error to the operator (see _sg_member_add).
    my $perr = policy_refresh();
    my %out = ( removed => JSON::true, group_id => $id + 0, node_id => $nid + 0 );
    $out{policy_warning} = join('; ', @$perr) if $perr && @$perr;
    return API::Response->ok(\%out);
}
sub _sg_ipg_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(ip_group_id)]); return $bad if $bad;
    my ($ok, $err) = secondary_group_ip_group_add($id, $b->{ip_group_id});
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_ip_group_add', 'secondary_group', $id, { after => { ip_group_id => ($b->{ip_group_id} // '')+0 } });
        # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
        my $perr = policy_refresh();
    my %out = ( added => JSON::true );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}
sub _sg_ipg_del {
    my ($self, $id, $ipgid) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($ok, $err) = secondary_group_ip_group_remove($id, $ipgid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_ip_group_remove', 'secondary_group', $id, { before => { ip_group_id => $ipgid + 0 } });
        # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
        my $perr = policy_refresh();
    my %out = ( removed => JSON::true );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}
# Body: {tsig_key_id} to bind an existing key, OR {name,algorithm,secret} to create and bind atomically (no orphan).
sub _sg_tsig_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(tsig_key_id name algorithm secret)]); return $bad if $bad;
    my ($ok, $err);
    my $kid;
    if (defined $b->{tsig_key_id}) { ($ok, $err) = secondary_group_tsig_key_add($id, $b->{tsig_key_id}); $kid = $b->{tsig_key_id}+0 unless $err; }
    else { ($kid, $err) = secondary_group_tsig_key_create_and_add($id, $b->{name}, $b->{algorithm}, $b->{secret}); }
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_tsig_key_add', 'secondary_group', $id, { after => { tsig_key_id => (defined $kid ? $kid+0 : undef), name => $b->{name} } });
        # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
        my $perr = policy_refresh();
    my %out = ( added => JSON::true, tsig_key_id => (defined $kid ? $kid+0 : undef) );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}
sub _sg_tsig_primary {
    my ($self, $gid, $kid) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($ok, $err) = secondary_group_tsig_set_primary($gid, $kid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_tsig_primary', 'secondary_group', $gid, { after => { tsig_key_id => $kid + 0 } });
        # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
        my $perr = policy_refresh();
    my %out = ( primary => JSON::true );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok(\%out);
}
# A key lives while something references it: once the last reference is removed it leaves the panel and
# PowerDNS (the panel has no key store to sweep later). Strictly AFTER policy_refresh(): before it the key
# is still in the zones' TSIG-ALLOW-AXFR, and the sweep would see that reference and leave it.
sub _tsig_sweep {
    my ($user, $out, $name) = @_;
    # With a name, targeted: one zone's upstream reference was removed, no need to check every key.
    my ($gone, $err) = (defined $name && length $name)
        ? tsig_key_forget_unused_by_name($name) : tsig_keys_forget_unused();
    $out->{tsig_warning} = $err if $err;   # the key stayed: say so explicitly
    _inv_audit($user, 'tsig_key_delete', 'tsig_key', $_->{id}, { before => { name => $_->{name} }, detail => 'unused after unbind' })
        for @{ $gone || [] };
    return;
}
sub _sg_tsig_del {
    my ($self, $id, $kid) = @_;
    my ($user, $deny) = $self->_cap_ok('distribution.manage'); return $deny if $deny;
    my ($ok, $err) = secondary_group_tsig_key_remove($id, $kid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_group_tsig_key_remove', 'secondary_group', $id, { before => { tsig_key_id => $kid + 0 } });
    # AXFR authorisation input changed -> recompute the policy NOW (see _ipg_member_add).
    my $perr = policy_refresh();
    my %out = ( removed => JSON::true );
    $out{policy_warning} = join('; ', @$perr) if @$perr;
    _tsig_sweep($user, \%out);
    return API::Response->ok(\%out);
}

# ---- Secondary servers: a simple shell over nodes/endpoints/groups/ACL (secondary.manage) ----
my @SERVER_FIELDS = qw(name ip description group_ids enabled notify_policy axfr_policy);
# Fields that affect DISTRIBUTION: recipient address, group membership, enabled and both policies. Name and
# description don't, so they don't justify recomputing every zone.
# Values before and after are compared, not field presence: the form always sends the full set, so
# "field present" meant "always recompute".
my %DELIVERY_FIELDS = map { $_ => 1 } qw(ip enabled notify_policy axfr_policy);
sub _delivery_changed {
    my ($before, $after) = @_;
    return 1 unless $before;                       # a new server: nothing to compare
    for my $f (keys %DELIVERY_FIELDS) {
        my ($x, $y) = ($before->{$f}, $after->{$f});
        next if !defined $x && !defined $y;
        return 1 if !defined $x || !defined $y || "$x" ne "$y";
    }
    # Group membership is compared as a set: order means nothing.
    my $gb = join(',', sort { $a <=> $b } map { $_->{id} + 0 } @{ $before->{groups} || [] });
    my $ga = join(',', sort { $a <=> $b } map { $_->{id} + 0 } @{ $after->{groups}  || [] });
    return 1 if $gb ne $ga;
    return 0;
}
sub _srv_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($rows, $err) = secondary_servers_list(); return _inv_fail($err) if $err;
    return API::Response->ok({ servers => $rows });
}
# Server change history (audit_log with target_type='secondary_node'), like GET /zones/:id/audit.
sub _srv_audit {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    return API::Response->ok({ history => audit_history('secondary_node', "$id", 50) });
}
sub _srv_get {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($s, $err) = secondary_server_get($id); return _inv_fail($err) if $err;
    return API::Response->ok($s);
}
sub _srv_create {
    my ($self) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body(\@SERVER_FIELDS); return $bad if $bad;
    # notify_policy/axfr_policy are delivery policy (like a group's send_notify), so they need their own capability.
    if (exists $b->{notify_policy} || exists $b->{axfr_policy}) { (my $u, my $d) = $self->_cap_ok('distribution.manage'); return $d if $d; }
    my ($s, $err) = secondary_server_save($b); return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_server_save', 'secondary_node', $s->{id}, { after => $s });
    my $nerr = policy_refresh();   # a new server may land in catalog(s) right away through its group
    return API::Response->created(@$nerr ? { %$s, policy_warning => join('; ', @$nerr) } : $s);
}
sub _srv_update {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body(\@SERVER_FIELDS); return $bad if $bad;
    if (exists $b->{notify_policy} || exists $b->{axfr_policy}) { (my $u, my $d) = $self->_cap_ok('distribution.manage'); return $d if $d; }
    $b->{id} = $id + 0;
    my ($before) = secondary_server_get($id + 0);
    my ($s, $err) = secondary_server_save($b); return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_server_save', 'secondary_node', $id, { before => $before, after => $s });
    # Recompute only if something distribution depends on REALLY changed. The saved intent is NOT rolled back
    # when PowerDNS is unavailable: return a warning, the background pass will converge.
    return API::Response->ok($s) unless _delivery_changed($before, $s);
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { %$s, policy_warning => join('; ', @$nerr) } : $s);
}

# Direct assignment of a server to catalogs (Servers tab is the only place). Full replacement, atomic.
sub _srv_catalogs_set {
    my ($self, $id) = @_;
    # Catalog membership, so it needs the catalog capability, like the Catalog tab itself.
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(catalog_ids)]); return $bad if $bad;
    # The form sends assignments on every server save, even unchanged; an unchanged set is no reason to
    # recompute distribution for all zones. Sorting is only for a stable order: a numeric sort can't be used
    # here because $b is the request-body lexical and shadows the sort variable ("my $b used in sort comparison").
    my ($was) = nodes_catalogs_map();
    my $before = join(',', sort @{ [ map { $_ + 0 } @{ ($was || {})->{ $id + 0 } || [] } ] });
    my ($ok, $err, $clean) = node_catalogs_set($id + 0, $b->{catalog_ids}); return _inv_fail($err) if $err;
    my $after = join(',', sort @{ [ map { $_ + 0 } @{ $clean || [] } ] });
    return API::Response->ok({ node_id => $id + 0, catalog_ids => $clean }) if $before eq $after;
    _inv_audit($user, 'node_catalogs_set', 'secondary_node', $id,
               { before => { catalog_ids => [ grep { length } split /,/, $before ] }, after => { catalog_ids => $clean } });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { node_id => $id + 0, catalog_ids => $clean, policy_warning => join('; ', @$nerr) }
                                    : { node_id => $id + 0, catalog_ids => $clean });
}

# Server default group (its key is the authorisation; priority: own TSIG -> default group -> IP). null clears it.
sub _srv_default_group {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(group_id)]); return $bad if $bad;
    my ($ok, $err) = secondary_node_set_default_group($id, $b->{group_id}); return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_default_group', 'secondary_node', $id, { after => { group_id => (defined $b->{group_id} ? $b->{group_id}+0 : undef) } });
    # Changing the AUTHORISATION group changes TSIG/ACL of every distribution of this server -> refresh now,
    # or PowerDNS keeps the old authorisation until the worker runs.
    my $perr = policy_refresh();
    my ($srv, $ge) = secondary_server_get($id); return _inv_fail($ge) if $ge;
    $srv->{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok($srv);   # updated server (incl. effective_auth); JS doesn't recompute auth
}

# Server's own TSIG keys (multiple + active). distribution.manage (this is AXFR authorisation).
# Body: {tsig_key_id} to bind an existing key, OR {name,algorithm,secret} to create and bind atomically (no orphan).
sub _srv_tsig_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(tsig_key_id name algorithm secret)]); return $bad if $bad;
    my ($ok, $err);
    if (defined $b->{tsig_key_id}) { ($ok, $err) = secondary_node_tsig_key_add($id, $b->{tsig_key_id}); }
    else { ($ok, $err) = secondary_node_tsig_key_create_and_add($id, $b->{name}, $b->{algorithm}, $b->{secret}); }
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_tsig_key_add', 'secondary_node', $id, { after => { tsig_key_id => (defined $b->{tsig_key_id} ? $b->{tsig_key_id}+0 : undef), name => $b->{name} } });
    # The server's own TSIG is also an AXFR authorisation input: refresh now.
    my $perr = policy_refresh();
    my ($srv, $ge) = secondary_server_get($id); return _inv_fail($ge) if $ge;
    $srv->{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok($srv);
}
sub _srv_tsig_primary {
    my ($self, $id, $kid) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($ok, $err) = secondary_node_tsig_set_primary($id, $kid); return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_tsig_primary', 'secondary_node', $id, { after => { tsig_key_id => $kid + 0 } });
    # The server's own TSIG is also an AXFR authorisation input: refresh now.
    my $perr = policy_refresh();
    my ($srv, $ge) = secondary_server_get($id); return _inv_fail($ge) if $ge;
    $srv->{policy_warning} = join('; ', @$perr) if @$perr;
    return API::Response->ok($srv);
}
sub _srv_tsig_del {
    my ($self, $id, $kid) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($ok, $err) = secondary_node_tsig_key_remove($id, $kid); return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_tsig_key_remove', 'secondary_node', $id, { before => { tsig_key_id => $kid + 0 } });
    # The server's own TSIG is also an AXFR authorisation input: refresh now.
    my $perr = policy_refresh();
    my ($srv, $ge) = secondary_server_get($id); return _inv_fail($ge) if $ge;
    $srv->{policy_warning} = join('; ', @$perr) if @$perr;
    _tsig_sweep($user, $srv);
    return API::Response->ok($srv);
}
sub _srv_delete {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my $label = audit_target_label('secondary_node', $id);   # name snapshot BEFORE deletion
    my ($ok, $err) = secondary_server_delete($id); return _inv_fail($err) if $err;   # clears ACLs before deleting the node
    _inv_audit($user, 'secondary_server_delete', 'secondary_node', $id, { label => $label });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { deleted => 1, policy_warning => join('; ', @$nerr) } : { deleted => 1 });
}

# ---- Secondary nodes (secondary.manage) ----
sub _sn_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($rows, $err) = secondary_nodes_all();
    return _inv_fail($err) if $err;
    return API::Response->ok({ nodes => $rows });
}
sub _sn_get {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_inv_read_ok; return $deny if $deny;
    my ($n, $err) = secondary_node_get($id);
    return _inv_fail($err) if $err;
    return API::Response->ok({ node => $n });
}
my @NODE_FIELDS = qw(name location enabled implementation provisioning_mode supports_catalog supports_coo notify_policy axfr_policy);
sub _sn_create {
    my ($self) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body(\@NODE_FIELDS); return $bad if $bad;
    if (exists $b->{notify_policy} || exists $b->{axfr_policy}) { (my $u, my $d) = $self->_cap_ok('distribution.manage'); return $d if $d; }
    my ($id, $err) = secondary_node_create($b);
    return _inv_fail($err) if $err;
    my ($after, $d) = _snap_after('secondary_node', $id);
    _inv_audit($user, 'secondary_node_create', 'secondary_node', $id, { after => $after, detail => $d });
    return API::Response->created({ id => $id + 0 });
}
sub _sn_update {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body(\@NODE_FIELDS, patch => 1); return $bad if $bad;
    if (exists $b->{notify_policy} || exists $b->{axfr_policy}) { (my $u, my $d) = $self->_cap_ok('distribution.manage'); return $d if $d; }
    my ($before, $bderr) = _snap_before('secondary_node', $id); return $bderr if $bderr;
    my ($ok, $err) = secondary_node_update($id, $b);
    return _inv_fail($err) if $err;
    my ($after, $d) = _snap_after('secondary_node', $id);
    _inv_audit($user, 'secondary_node_update', 'secondary_node', $id, { before => $before, after => $after, detail => $d });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { updated => JSON::true, id => $id + 0, policy_warning => join('; ', @$nerr) }
                                    : { updated => JSON::true, id => $id + 0 });
}
sub _sn_delete {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($before, $bderr) = _snap_before('secondary_node', $id); return $bderr if $bderr;
    my ($ok, $err) = secondary_server_delete($id);   # clears ACLs, then deletes the node (no stale /32 entries)
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_delete', 'secondary_node', $id, { before => $before });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { deleted => JSON::true, id => $id + 0, policy_warning => join('; ', @$nerr) }
                                    : { deleted => JSON::true, id => $id + 0 });
}
sub _sn_ep_add {
    my ($self, $id) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(purpose address port enabled)]); return $bad if $bad;
    my ($eid, $err, $canon) = secondary_node_endpoint_add($id, $b->{purpose}, $b->{address}, $b->{port}, $b->{enabled});
    return _inv_fail($err) if $err;
    my ($after, $ae) = secondary_node_endpoint_get($id, $eid);
    _inv_audit($user, 'secondary_node_endpoint_add', 'secondary_node', $id,
               { after => ($after || { endpoint_id => $eid+0, purpose => $b->{purpose}, address => $canon }), detail => ($ae ? "after-snapshot unavailable: $ae" : undef) });
    my $nerr = policy_refresh();   # notify_target/dns_listen is the NOTIFY address itself
    return API::Response->created(@$nerr ? { id => $eid + 0, address => $canon, policy_warning => join('; ', @$nerr) }
                                         : { id => $eid + 0, address => $canon });
}
sub _sn_ep_update {
    my ($self, $id, $eid) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(purpose address port enabled)], patch => 1); return $bad if $bad;
    my ($before, $be) = secondary_node_endpoint_get($id, $eid); return _inv_fail($be) if $be;
    my ($ok, $err) = secondary_node_endpoint_update($id, $eid, $b);
    return _inv_fail($err) if $err;
    my ($after, $ae) = secondary_node_endpoint_get($id, $eid);
    _inv_audit($user, 'secondary_node_endpoint_update', 'secondary_node', $id,
               { before => $before, after => $after, detail => ("endpoint $eid".($ae ? "; after-snapshot unavailable: $ae" : '')) });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { updated => JSON::true, id => $eid + 0, policy_warning => join('; ', @$nerr) }
                                    : { updated => JSON::true, id => $eid + 0 });
}
sub _sn_ep_del {
    my ($self, $id, $eid) = @_;
    my ($user, $deny) = $self->_cap_ok('secondary.manage'); return $deny if $deny;
    my ($before, $be) = secondary_node_endpoint_get($id, $eid); return _inv_fail($be) if $be;
    my ($ok, $err) = secondary_node_endpoint_delete($id, $eid);
    return _inv_fail($err) if $err;
    _inv_audit($user, 'secondary_node_endpoint_delete', 'secondary_node', $id, { before => $before });
    my $nerr = policy_refresh();
    return API::Response->ok(@$nerr ? { deleted => JSON::true, id => $eid + 0, policy_warning => join('; ', @$nerr) }
                                    : { deleted => JSON::true, id => $eid + 0 });
}

# ============================================================================
# CATALOGS and ZONE DISTRIBUTION: two areas with two capabilities. Catalogs themselves (list, create,
# delete, subscribers) need catalog.manage. Distribution of a SPECIFIC zone (direct and catalog listing)
# needs distribution.manage. Error contract and audit as in the inventory (_inv_fail/_inv_audit).
# ============================================================================
sub _dist_ok { my ($self) = @_; return $self->_cap_ok('distribution.manage'); }
sub _zones_ok { my ($self) = @_; return $self->_cap_ok('zones.manage'); }
# Catalogs are a SELF-CONTAINED area with their own capability. Previously distribution.manage was also
# required, and a user with only "Manage catalogs" saw a closed page without knowing what was missing.
# Assigning a SPECIFIC zone to a catalog is still a zone distribution decision (see _zcatalog_set).
sub _cat_ok  { my ($self) = @_; return $self->_cap_ok('catalog.manage'); }
sub _cat_list {
    my ($self) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($r, $e) = catalogs_all(); return _inv_fail($e) if $e;
    return API::Response->ok({ catalogs => $r });
}
sub _cat_get {
    my ($self, $cid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($c, $e) = catalog_get($cid + 0); return _inv_fail($e) if $e;
    my ($g)  = catalog_groups_get($cid + 0);
    my ($n)  = catalog_nodes_get($cid + 0);
    my ($z)  = catalog_zones($cid + 0);
    # Per-server status for the catalog's Servers tab: authorization, NOTIFY, subscription.
    my ($cons, $ce) = catalog_consumers_state($cid + 0); return _inv_fail($ce) if $ce;
    return API::Response->ok({ %$c, group_ids => ($g || []), node_ids => ($n || []), zones => ($z || []), consumers => $cons });
}
# Catalog creation is ONE action: the row plus the producer zone in PowerDNS. No plan or confirmation.
sub _cat_create {
    my ($self) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name fqdn group_ids)]); return $bad if $bad;
    my ($c, $e) = catalog_create({ name => $b->{name}, fqdn => $b->{fqdn} }); return _inv_fail($e) if $e;
    if (ref $b->{group_ids} eq 'ARRAY') {
        my (undef, $ge) = catalog_groups_set($c->{id}, $b->{group_ids});
        return _inv_fail($ge) if $ge;
    }
    _inv_audit($user, 'catalog_create', 'catalog', $c->{id}, { after => $c });
    my $perr = policy_refresh();
    return API::Response->created({ %$c, policy_warning => (@$perr ? join('; ', @$perr) : undef) });
}
sub _cat_update {
    my ($self, $cid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name fqdn)], patch => 1); return $bad if $bad;
    my ($before) = catalog_get($cid + 0);
    my ($c, $e) = catalog_update($cid + 0, $b); return _inv_fail($e) if $e;
    _inv_audit($user, 'catalog_update', 'catalog', $cid, { before => $before, after => $c });
    return API::Response->ok($c);
}
# Deleting a catalog takes its zones out, so they stop being announced to subscribers. Hence the
# confirmation, and the response says how many zones are affected.
sub _cat_delete {
    my ($self, $cid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($before, $ge) = catalog_get($cid + 0); return _inv_fail($ge) if $ge;
    my ($zs, $ze) = catalog_zones($cid + 0); return _inv_fail($ze) if $ze;
    my $q = $self->{cgi};
    my $confirm = ($q && $q->param('confirm')) ? 1 : 0;
    if (@$zs && !$confirm) {
        return API::Response->bad_request(
            sprintf('catalog still announces %d zone(s) — they will stop being announced; repeat with ?confirm=1',
                    scalar @$zs));
    }
    my ($r, $e) = catalog_delete($cid + 0); return _inv_fail($e) if $e;
    _inv_audit($user, 'catalog_delete', 'catalog', $cid, { before => $before });
    return API::Response->ok({ deleted => JSON::true, zones_released => scalar @$zs });
}
# Idempotent: an already provisioned catalog just returns its state.
sub _cat_provision {
    my ($self, $cid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($c, $e) = catalog_provision($cid + 0); return _inv_fail($e) if $e;
    _inv_audit($user, 'catalog_provision', 'catalog', $cid, { after => $c });
    return API::Response->ok($c);
}
sub _cat_groups_set {
    my ($self, $cid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(group_ids)]); return $bad if $bad;
    my ($before) = catalog_groups_get($cid + 0);
    my ($r, $e) = catalog_groups_set($cid + 0, $b->{group_ids}); return _inv_fail($e) if $e;
    _inv_audit($user, 'catalog_groups_set', 'catalog', $cid, { before => { group_ids => $before }, after => { group_ids => $r } });
    # Subscribers change zone permissions: converge now, not at the next worker pass.
    my $perr = policy_refresh();
    return API::Response->ok({ group_ids => $r, policy_warning => (@$perr ? join('; ', @$perr) : undef) });
}
sub _cat_node_remove {
    my ($self, $cid, $nid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($r, $e) = catalog_node_remove($cid + 0, $nid + 0); return _inv_fail($e) if $e;
    _inv_audit($user, 'catalog_node_remove', 'catalog', $cid, { before => { node_id => $nid + 0 } });
    my $perr = policy_refresh();
    return API::Response->ok({ removed => JSON::true, policy_warning => (@$perr ? join('; ', @$perr) : undef) });
}
sub _cat_sub_config {
    my ($self, $cid, $nid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($r, $e) = catalog_subscription_config($cid + 0, $nid + 0); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}
sub _cat_sub_recheck {
    my ($self, $cid, $nid) = @_;
    my ($user, $deny) = $self->_cat_ok; return $deny if $deny;
    my ($r, $e) = catalog_subscription_recheck($cid + 0, $nid + 0); return _inv_fail($e) if $e;
    return API::Response->ok($r);
}

sub _zdist_get {
    my ($self, $did) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my $dbh = functions::connectDB() or return _inv_fail('DB unavailable');
    my ($r, $e) = zone_recipients($dbh, $did + 0); return _inv_fail($e) if $e;
    my ($cats, $ce) = catalogs_available(); return _inv_fail($ce) if $ce;
    my %fq = map { $_->{catalog_id} => $_->{fqdn} } @$cats;
    my @list = map { { catalog_id => $_->{catalog_id}, name => $_->{name}, fqdn => $_->{fqdn},
                       provisioned => ($_->{provisioned} ? JSON::true : JSON::false) } } @$cats;
    return API::Response->ok({
        domain_id  => $did + 0,
        direct     => ($r->{direct} ? JSON::true : JSON::false),
        catalog_id => $r->{catalog_id},
        catalog_fqdn => ($r->{catalog_id} ? $fq{ $r->{catalog_id} } : undef),
        recipients => [ map { { node_id => $_->{node_id}, name => $_->{name}, source => $_->{source} } } @{ $r->{consumers} } ],
        catalogs   => \@list,
    });
}
# A single zone goes through the SAME path as the bulk one, so the write rule and the response shape match.
# A separate single-zone implementation once answered "Direct AXFR not changed" for an already saved value.
sub _zdirect_set {
    my ($self, $did) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(on reason)]); return $bad if $bad;
    my $v = $b->{on};
    return API::Response->bad_request('on must be a JSON boolean (true/false)')
        unless defined $v && JSON::is_bool($v);
    return $self->_zdirect_apply($user, [$did + 0], ($v ? 1 : 0), $b->{reason});
}
# Secondary -> Primary. Distribution is untouched: direct AXFR and catalog are properties of the zone, not
# of its type. Both are returned AS THEY ARE, so the screen doesn't show the "before" state.
sub _zone_promote {
    my ($self, $id) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required") unless has_capability($user, 'zones.manage');
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    # ignore_source_serial covers one case: the old server is off and there is nothing to compare against.
    # It is a deliberate per-zone decision, so bulk promotion doesn't offer it.
    # dynamic: accept RFC 2136 updates right away (the dialog sets it for a migrated dynamic zone).
    my ($b, $bad) = _strict_body([qw(confirm_name ignore_source_serial dynamic)]); return $bad if $bad;
    my $want = defined $b->{confirm_name} ? $b->{confirm_name} : '';
    return API::Response->bad_request('confirm_name must match the zone name')
        unless lc($want) eq lc($zone->{name} // '');
    my ($res, $err) = zone_promote_to_primary($id + 0, { skip_source_check => ($b->{ignore_source_serial} ? 1 : 0),
                                                           dynamic => ($b->{dynamic} ? 1 : 0) });
    return _inv_fail($err) if $err;
    _inv_audit($user, 'zone_promote_to_primary', 'zone', $id,
               { before => { type => 'SLAVE', master => $zone->{master} },
                 after  => { type => 'MASTER', dynamic => $res->{dynamic} } });
    my %out = ( promoted => JSON::true, id => $id + 0, zone => $res->{zone},
                direct => ($res->{direct} ? JSON::true : JSON::false), catalog_id => $res->{catalog_id} );
    # Core warnings (upstream metadata not removed, confirmation read from the DB) must reach the user.
    $out{warnings} = $res->{warnings} if @{ $res->{warnings} || [] };
    _tsig_sweep($user, \%out, $res->{tsig_released});   # upstream removed: the key may now have no references
    return API::Response->ok(\%out);
}

# POST /zones/:id/demote: hand the zone to a foreign primary (Primary -> Secondary). zones.manage + name
# confirmation, as for the reverse operation: it is one-way (back only via Make primary) and replaces all
# records. distribution.manage is required ONLY if the zone is in a catalog: removing it from there is a
# distribution change, and a zone without a catalog has no such step.
sub _zone_demote {
    my ($self, $id) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required") unless has_capability($user, 'zones.manage');
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    my ($b, $bad) = _strict_body([qw(confirm_name masters tsig tsig_new)]); return $bad if $bad;
    my $want = defined $b->{confirm_name} ? $b->{confirm_name} : '';
    return API::Response->bad_request('confirm_name must match the zone name')
        unless lc($want) eq lc($zone->{name} // '');
    my ($cur_cat) = zone_catalog_of(functions::connectDB(), $id + 0);
    if ($cur_cat) {
        return API::Response->forbidden("Capability 'distribution.manage' required to take the zone out of its catalog")
            unless has_capability($user, 'distribution.manage');
    }
    my ($tsig, $made, $te) = upstream_tsig_resolve($b->{tsig}, $b->{tsig_new}); return _inv_fail($te) if $te;
    my ($res, $err) = zone_demote_to_secondary($id + 0, { masters => $b->{masters}, tsig => $tsig });
    if ($err) { upstream_tsig_rollback($made); return _inv_fail($err); }
    _inv_audit($user, 'zone_demote_to_secondary', 'zone', $id,
               { before => { type => uc($zone->{type} // ''), catalog_id => $cur_cat },
                 after  => { type => 'SLAVE', masters => $res->{masters}, tsig => $res->{tsig} } });
    my %out = ( demoted => JSON::true, id => $id + 0, zone => $res->{zone},
                masters => $res->{masters}, tsig => $res->{tsig},
                catalog_removed => ($res->{catalog_removed} ? JSON::true : JSON::false),
                direct => ($res->{direct} ? JSON::true : JSON::false),
                pdns_state => $res->{sync}{pdns_state}, pdns_detail => $res->{sync}{detail} );
    $out{warnings} = $res->{warnings} if @{ $res->{warnings} || [] };
    return API::Response->ok(\%out);
}
# GET /zones/upstream-keys: keys a secondary zone can sign its transfer with (names only, never secrets).
sub _zone_upstream_keys {
    my ($self) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required") unless has_capability($user, 'zones.manage');
    my ($keys, $e) = upstream_tsig_keys(); return _inv_fail($e) if $e;
    return API::Response->ok({ keys => $keys });
}
# Where a secondary zone comes from: primary addresses and TSIG. Downstream distribution is not touched.
sub _zone_secondary_source {
    my ($self, $id) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    return API::Response->forbidden("Capability 'zones.manage' required") unless has_capability($user, 'zones.manage');
    my $zone = pdns_get_domain($id) or return API::Response->not_found('Zone not found');
    # renotify (SLAVE-RENOTIFY) is NOT accepted here: it is onward distribution, derived from policy.
    # The field is rejected outright; a silently ignored field would look like an accepted setting.
    my ($b, $bad) = _strict_body([qw(masters tsig tsig_new request_id)]); return $bad if $bad;
    my ($tsig, $made, $te) = upstream_tsig_resolve($b->{tsig}, $b->{tsig_new}); return _inv_fail($te) if $te;

    my $meta0 = pdns_get_domain_metadata($id) || {};
    my $before = { masters => [ grep { length } split /\s*,\s*/, ($zone->{master} // '') ],
                   tsig    => (($meta0->{'AXFR-MASTER-TSIG'} && @{ $meta0->{'AXFR-MASTER-TSIG'} }) ? $meta0->{'AXFR-MASTER-TSIG'}[0] : '') };

    my ($res, $err) = zone_secondary_source_set($id + 0, { masters => $b->{masters}, tsig => $tsig });
    if ($err) { upstream_tsig_rollback($made); return _inv_fail($err); }
    _inv_audit($user, 'zone_source_set', 'zone', $zone->{name},
               { before => $before, after => { masters => $res->{masters}, tsig => $res->{tsig} } });

    # Request AXFR right away via the same core as "Refresh AXFR" (always retrieve): otherwise a zone already
    # being served would keep old content until the next SOA refresh. The source change reset last_check, so
    # the zone counts as pending until PowerDNS checks the NEW primary. A failed request does NOT roll back the
    # source: the new address is saved and the state is reported.
    my $sync = zone_secondary_refresh($zone->{name});
    my @w = @{ $res->{warnings} || [] };
    push @w, ($sync->{requested} ? "transfer requested, but " : "transfer not requested: ") . $sync->{error} if $sync->{error};
    my %out = (
        zone => $res->{zone}, masters => $res->{masters}, tsig => $res->{tsig},
        sync => { pdns_state => $sync->{pdns_state} },
        (@w ? (warnings => \@w) : ()) );
    _tsig_sweep($user, \%out, $res->{tsig_released});   # the previous key may now have no references
    return API::Response->ok(\%out);
}
# Bulk enable/disable, also used by the single-zone edit. Answers with the LIST applied and the list refused:
# partial success happens (PowerDNS may fail for one zone) and must not be reported as full.
sub _zdirect_bulk {
    my ($self) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(domain_ids on reason)]); return $bad if $bad;
    my $v = $b->{on};
    return API::Response->bad_request('on must be a JSON boolean (true/false)')
        unless defined $v && JSON::is_bool($v);
    return API::Response->bad_request('domain_ids must be a non-empty array')
        unless ref $b->{domain_ids} eq 'ARRAY' && @{ $b->{domain_ids} };
    return $self->_zdirect_apply($user, $b->{domain_ids}, ($v ? 1 : 0), $b->{reason});
}
# The ONLY implementation. saved is what the panel stored (intent), zones is each zone's state after apply,
# failed is what did not reach PowerDNS. saved and applied can differ; that is not "nothing changed": the
# intent is saved and the background pass will finish it.
sub _zdirect_apply {
    my ($self, $user, $ids, $on, $reason) = @_;
    my ($r, $e) = zones_direct_axfr_set($ids, $on, $reason); return _inv_fail($e) if $e;
    _inv_audit($user, 'zone_direct_axfr_set', 'zone', ((@{ $r->{saved} } == 1) ? $r->{saved}[0] : 0),
               { after => { direct => $on, domain_ids => $r->{saved} },
                 label => ((@{ $r->{saved} } == 1) ? undef : scalar(@{ $r->{saved} }) . ' zone(s)') });
    my @state = map { { domain_id => $_->{domain_id}, direct => ($_->{direct} ? JSON::true : JSON::false),
                        catalog_id => $_->{catalog_id} } } @{ $r->{zones} };
    return API::Response->ok({ zones => \@state, saved => $r->{saved}, failed => $r->{failed} });
}
# catalog_id = null means "remove from catalog". A missing key is distinguished from an explicit null, or
# "not sent" and "remove" would merge and a frontend slip would silently drop the announcement.
sub _zcatalog_set {
    my ($self, $did) = @_;
    my ($user, $deny) = $self->_dist_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(catalog_id reason)]); return $bad if $bad;
    return API::Response->bad_request('catalog_id required (integer or null)') unless exists $b->{catalog_id};
    my $cid = $b->{catalog_id};
    return API::Response->bad_request('catalog_id must be an integer or null')
        if defined $cid && "$cid" !~ /^\d+$/;
    my $dbh = functions::connectDB() or return _inv_fail('DB unavailable');
    my ($before) = zone_recipients($dbh, $did + 0);
    my ($r, $e) = zone_catalog_set($did + 0, $cid, $b->{reason}); return _inv_fail($e) if $e;
    _inv_audit($user, 'zone_catalog_set', 'zone', $did,
               { before => { catalog_id => ($before ? $before->{catalog_id} : undef) }, after => { catalog_id => $cid } });
    return $self->_zdist_get($did);
}

# ============================================================================
# ACCOUNT: the caller's own data only. The id comes from the session, never from the request, so there is
# nothing to forge. users.manage is not required: this is not administration.
# ============================================================================
sub _me { my ($self) = @_;
    my $u = _current_user($self);
    return (undef, API::Response->unauthorized('Authentication required')) unless $u;
    return ($u, undef);
}
sub _acct_get {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($info, $err) = account_overview($u->{id}, $self->_cur_session_id);
    return _inv_fail($err) if $err;
    $info->{themes} = account_themes();
    return API::Response->ok($info);
}
sub _acct_password {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(current_password new_password)]); return $bad if $bad;
    my ($ok, $err) = account_password_change($u->{id}, $b->{current_password}, $b->{new_password},
                                             $self->_cur_session_id);
    return _inv_fail($err) if $err;
    _inv_audit($u, 'account_password_change', 'user', $u->{id}, {});
    return API::Response->ok({ ok => JSON::true });
}
sub _acct_totp_begin {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($d, $err) = account_totp_begin($u->{id}, setting('auth.totp_issuer'));
    return _inv_fail($err) if $err;
    return API::Response->ok($d);
}
sub _acct_totp_confirm {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(code)]); return $bad if $bad;
    my ($codes, $err) = account_totp_confirm($u->{id}, $b->{code});
    return _inv_fail($err) if $err;
    _inv_audit($u, 'account_totp_replaced', 'user', $u->{id}, {});
    return API::Response->ok({ ok => JSON::true, recovery_codes => $codes });
}
# Turn off one's own second factor. The app code is required, as when issuing new recovery codes.
sub _acct_totp_off {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(code)]); return $bad if $bad;
    my ($ok, $err) = account_totp_disable($u->{id}, $b->{code});
    return _inv_fail($err) if $err;
    _inv_audit($u, 'account_totp_off', 'user', $u->{id}, {});
    return API::Response->ok({ ok => JSON::true });
}
sub _acct_totp_cancel {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($ok, $err) = account_totp_cancel($u->{id});
    return _inv_fail($err) if $err;
    return API::Response->ok({ ok => JSON::true });
}
sub _acct_recovery {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(code)]); return $bad if $bad;
    my ($codes, $err) = account_recovery_regenerate($u->{id}, $b->{code});
    return _inv_fail($err) if $err;
    _inv_audit($u, 'account_recovery_codes_new', 'user', $u->{id}, {});
    return API::Response->ok({ ok => JSON::true, recovery_codes => $codes });
}
sub _acct_prefs {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(timezone theme date_format)]); return $bad if $bad;
    my ($p, $err) = account_prefs_set($u->{id}, $b->{timezone}, $b->{theme}, $b->{date_format});
    return _inv_fail($err) if $err;
    return API::Response->ok($p);
}
# One's own sessions: same logic as for admins, but other users' ids are unreachable.
sub _acct_session_revoke {
    my ($self, $sid) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($n, $err) = session_revoke($u->{id}, $sid);
    return _inv_fail($err) if $err;
    return API::Response->not_found('Session not found') unless $n;
    _inv_audit($u, 'account_session_revoke', 'user', $u->{id}, { after => { session_id => $sid + 0 } });
    return API::Response->ok({ ok => JSON::true });
}
sub _acct_sessions_revoke_others {
    my ($self) = @_;
    my ($u, $deny) = $self->_me; return $deny if $deny;
    my ($n, $err) = session_revoke_all($u->{id}, $self->_cur_session_id);
    return _inv_fail($err) if $err;
    _inv_audit($u, 'account_sessions_revoke_others', 'user', $u->{id}, { after => { closed => $n + 0 } });
    return API::Response->ok({ ok => JSON::true, closed => $n + 0 });
}

# ============================================================================
# Users & access (Settings -> Users & access), all under users.manage; mutations are audited.
# Backend functions return (result, undef)|(undef, err); err -> HTTP via _inv_fail.
# The last-admin guard is in the backend (its refusal strings pass through as 409/400).
# ============================================================================
sub _users_ok { my ($self) = @_; return $self->_cap_ok('users.manage'); }

# ---- Users ----
sub _usr_list {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($rows, $err) = users_all(); return _inv_fail($err) if $err;
    return API::Response->ok({ users => $rows });
}
sub _usr_get {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($usr, $err) = user_get($id); return _inv_fail($err) if $err;
    return API::Response->ok({ user => $usr });
}
sub _usr_create {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(username display_name email is_active)]); return $bad if $bad;
    my ($id, $err) = user_create($b); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_create', 'user', $id, { after => { username => $b->{username} } });
    return API::Response->created({ id => $id + 0 });
}
sub _usr_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(username display_name email is_active)], patch => 1); return $bad if $bad;
    my ($ok, $err) = user_update($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_update', 'user', $id, { detail => { fields => [ sort keys %$b ] } });
    return API::Response->ok({ updated => JSON::true, id => $id + 0 });
}
sub _usr_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $label = _audit_label('user', $id);   # name snapshot BEFORE deletion
    my ($ok, $err) = user_delete($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_delete', 'user', $id, { label => $label });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}
# Reset/set password: body {password?}; if empty a temporary one is generated. must_change=1; temp_password is shown once.
sub _usr_password {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(password reset_totp)]); return $bad if $bad;
    # reset_totp is EXPLICIT and a real boolean only. Resetting the second factor along with the password
    # "just in case" would make "forgot password" mean "lost 2FA"; forbidding it would make someone who lost
    # both come twice.
    my $rt = 0;
    if (defined $b->{reset_totp}) {
        return API::Response->bad_request('reset_totp must be a JSON boolean') unless JSON::is_bool($b->{reset_totp});
        $rt = $b->{reset_totp} ? 1 : 0;
    }
    my $pw = (defined $b->{password} && length $b->{password}) ? $b->{password} : functions::_gen_temp_password();
    my ($ok, $err) = set_user_password($id, $pw, 1); return _inv_fail($err) if $err;
    if ($rt) {
        # "Lost the phone too" is a reset: the second factor stays required, and the user enrols the app again
        # at the first login with the temporary password.
        my ($tok, $terr) = auth_totp_reset($id); return _inv_fail($terr) if $terr;
    }
    _inv_audit($u, ($rt ? 'user_access_recovered' : 'user_password_reset'), 'user', $id, { after => { totp_reset => $rt } });
    return API::Response->ok({ ok => JSON::true, temp_password => $pw, totp_reset => ($rt ? JSON::true : JSON::false) });
}
# Reset the app (lost phone or reinstalled app). The old one is unbound but the second factor stays required;
# the next login asks to enrol a new one.
sub _usr_totp_reset {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = auth_totp_reset($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'totp_reset', 'user', $id, {});
    return API::Response->ok({ ok => JSON::true });
}
# Require a second factor from someone who has no app yet (or stop requiring it).
sub _usr_totp_required {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(required)]); return $bad if $bad;
    return API::Response->bad_request('required must be a JSON boolean') unless JSON::is_bool($b->{required});
    my $on = $b->{required} ? 1 : 0;
    my ($ok, $err) = auth_totp_require($id, $on); return _inv_fail($err) if $err;
    _inv_audit($u, ($on ? 'totp_required' : 'totp_not_required'), 'user', $id, {});
    return API::Response->ok({ ok => JSON::true, required => ($on ? JSON::true : JSON::false) });
}
# Turn the second factor off entirely. The user can turn it back on in Account.
sub _usr_totp_off {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = auth_totp_disable($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'totp_off', 'user', $id, {});
    return API::Response->ok({ ok => JSON::true });
}
sub _cur_session_id {   # the caller's current session id (to mark "current" in the list)
    my ($self) = @_;
    my $tok = $self->{cgi} ? $self->{cgi}->cookie('session_token') : undef;
    my $s = $tok ? session_by_raw($tok) : undef;
    return $s ? $s->{id} : undef;
}
sub _usr_sessions {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($rows, $err) = user_sessions($id, $self->_cur_session_id); return _inv_fail($err) if $err;
    my $ovr = user_session_ttl_raw($id);
    return API::Response->ok({ sessions => $rows, default_ttl => session_ttl_default() + 0,
                              session_ttl_override => (defined $ovr ? $ovr + 0 : undef), effective_ttl => user_session_ttl($id) + 0 });
}
sub _usr_session_revoke {
    my ($self, $id, $sid) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = session_revoke($id, $sid); return _inv_fail($err) if $err;
    _inv_audit($u, 'session_revoke', 'user', $id, { detail => { session => $sid + 0 } });
    return API::Response->ok({ revoked => $ok + 0 });
}
sub _usr_session_revoke_all {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $keep = ($self->{cgi} && $self->{cgi}->param('keep_current')) ? $self->_cur_session_id : undef;
    my ($n, $err) = session_revoke_all($id, $keep); return _inv_fail($err) if $err;
    _inv_audit($u, 'session_revoke_all', 'user', $id, { detail => { revoked => $n + 0 } });
    return API::Response->ok({ revoked => $n + 0 });
}
sub _usr_session_policy {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(ttl)]); return $bad if $bad;
    my ($ok, $err) = set_user_session_ttl($id, $b->{ttl}); return _inv_fail($err) if $err;
    _inv_audit($u, 'session_policy_set', 'user', $id, { detail => { ttl => (defined $b->{ttl} && $b->{ttl} ne '' ? $b->{ttl} + 0 : 'default') } });
    my $ovr = user_session_ttl_raw($id);
    return API::Response->ok({ ok => JSON::true, session_ttl_override => (defined $ovr ? $ovr + 0 : undef), effective_ttl => user_session_ttl($id) + 0 });
}
sub _usr_effective {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($res, $err) = zone_access_effective($id); return _inv_fail($err) if $err;
    return API::Response->ok($res);
}
# Atomic replacement of all personal access (direct caps + personal zone rules) in one transaction.
sub _usr_access_set {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(group_ids capabilities denied_capabilities zone_rules)]); return $bad if $bad;
    my ($ok, $err) = user_access_set($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_access_set', 'user', $id, { detail => { groups => scalar(@{ $b->{group_ids} || [] }), caps => scalar(@{ $b->{capabilities} || [] }), rules => scalar(@{ $b->{zone_rules} || [] }) } });
    # Return the CANONICAL saved object: JS rebuilds its draft from it without a second GET.
    my ($fresh, $ge) = user_get($id); return _inv_fail($ge) if $ge;
    return API::Response->ok({ user => $fresh });
}
# Draft preview of effective access WITHOUT saving (read-only, not audited). Same engine as enforcement.
sub _usr_access_preview {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(group_ids capabilities denied_capabilities zone_rules)]); return $bad if $bad;
    my ($res, $err) = user_access_preview($id, $b); return _inv_fail($err) if $err;
    return API::Response->ok($res);
}
sub _usr_group_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(group_id)]); return $bad if $bad;
    my ($ok, $err) = user_group_add($id, $b->{group_id}); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_group_add', 'user', $id, { detail => { group_id => $b->{group_id} } });
    return API::Response->ok({ ok => JSON::true });
}
sub _usr_group_del {
    my ($self, $id, $gid) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = user_group_remove($id, $gid); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_group_remove', 'user', $id, { detail => { group_id => $gid } });
    return API::Response->ok({ ok => JSON::true });
}
sub _usr_cap_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(capability effect)]); return $bad if $bad;
    # effect=deny is a personal DENY: a capability granted by a group does not apply to this user.
    my $eff = (defined $b->{effect} && $b->{effect} eq 'deny') ? 'deny' : 'allow';
    return API::Response->bad_request('effect must be allow or deny')
        if defined $b->{effect} && $b->{effect} !~ /^(allow|deny)$/;
    my ($ok, $err) = capability_grant('user', $id, $b->{capability}, $eff); return _inv_fail($err) if $err;
    _inv_audit($u, ($eff eq 'deny' ? 'capability_deny' : 'capability_grant'), 'user', $id,
               { detail => { capability => $b->{capability} } });
    return API::Response->ok({ ok => JSON::true });
}
sub _usr_cap_del {
    my ($self, $id, $cap) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = capability_revoke('user', $id, $cap); return _inv_fail($err) if $err;
    _inv_audit($u, 'capability_revoke', 'user', $id, { detail => { capability => $cap } });
    return API::Response->ok({ ok => JSON::true });
}
sub _usr_za_set {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(scope access zone_id)]); return $bad if $bad;
    my ($nid, $err) = zone_access_set('user', $id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_access_set', 'user', $id, { after => { scope => $b->{scope}, access => $b->{access} } });
    return API::Response->ok({ id => $nid + 0 });
}
sub _usr_za_del {
    my ($self, $rid) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = zone_access_delete($rid); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_access_delete', 'zone_access', $rid, {});
    return API::Response->ok({ deleted => JSON::true });
}
sub _usr_ident_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(type provider principal data)]); return $bad if $bad;
    my ($nid, $err) = auth_identity_add($id, $b->{type}, $b->{provider}, $b->{principal}, $b->{data});
    return _inv_fail($err) if $err;
    _inv_audit($u, 'auth_identity_add', 'user', $id, { after => { type => $b->{type}, principal => $b->{principal} } });
    return API::Response->created({ id => $nid + 0 });
}
sub _usr_ident_del {
    my ($self, $iid) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $label = audit_target_label('auth_identity', $iid);   # CN/principal snapshot BEFORE deletion
    my ($ok, $err) = auth_identity_delete($iid); return _inv_fail($err) if $err;
    _inv_audit($u, 'auth_identity_delete', 'auth_identity', $iid, { label => $label });
    return API::Response->ok({ deleted => JSON::true });
}

# ---- Permission groups (table groups, NOT secondary_groups) ----
sub _pg_list {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($rows, $err) = perm_groups_all(); return _inv_fail($err) if $err;
    return API::Response->ok({ groups => $rows });
}
sub _pg_get {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($g, $err) = perm_group_get($id); return _inv_fail($err) if $err;
    return API::Response->ok({ group => $g });
}
sub _pg_create {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)]); return $bad if $bad;
    my ($id, $err) = perm_group_create($b); return _inv_fail($err) if $err;
    _inv_audit($u, 'perm_group_create', 'group', $id, { after => { name => $b->{name} } });
    return API::Response->created({ id => $id + 0 });
}
sub _pg_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)], patch => 1); return $bad if $bad;
    my ($ok, $err) = perm_group_update($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'perm_group_update', 'group', $id, { detail => { fields => [ sort keys %$b ] } });
    return API::Response->ok({ updated => JSON::true, id => $id + 0 });
}
sub _pg_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $label = _audit_label('group', $id);   # name snapshot BEFORE deletion
    my ($ok, $err) = perm_group_delete($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'perm_group_delete', 'group', $id, { label => $label });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}
sub _pg_member_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(user_id)]); return $bad if $bad;
    my ($ok, $err) = user_group_add($b->{user_id}, $id); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_group_add', 'group', $id, { detail => { user_id => $b->{user_id} } });
    return API::Response->ok({ ok => JSON::true });
}
sub _pg_member_del {
    my ($self, $id, $uid) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = user_group_remove($uid, $id); return _inv_fail($err) if $err;
    _inv_audit($u, 'user_group_remove', 'group', $id, { detail => { user_id => $uid } });
    return API::Response->ok({ ok => JSON::true });
}
sub _pg_cap_add {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(capability)]); return $bad if $bad;
    my ($ok, $err) = capability_grant('group', $id, $b->{capability}); return _inv_fail($err) if $err;
    _inv_audit($u, 'capability_grant', 'group', $id, { detail => { capability => $b->{capability} } });
    return API::Response->ok({ ok => JSON::true });
}
sub _pg_cap_del {
    my ($self, $id, $cap) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($ok, $err) = capability_revoke('group', $id, $cap); return _inv_fail($err) if $err;
    _inv_audit($u, 'capability_revoke', 'group', $id, { detail => { capability => $cap } });
    return API::Response->ok({ ok => JSON::true });
}
sub _pg_access_set {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(capabilities zone_rules)]); return $bad if $bad;
    my ($ok, $err) = group_access_set($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'group_access_set', 'group', $id, { detail => { caps => scalar(@{ $b->{capabilities} || [] }), rules => scalar(@{ $b->{zone_rules} || [] }) } });
    return API::Response->ok({ ok => JSON::true });
}
sub _pg_za_set {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(scope access zone_id)]); return $bad if $bad;
    my ($nid, $err) = zone_access_set('group', $id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'zone_access_set', 'group', $id, { after => { scope => $b->{scope}, access => $b->{access} } });
    return API::Response->ok({ id => $nid + 0 });
}

# ============================================================================
# NS PULSE: testers, their groups, checks and record switching rules.
# One capability for the whole section (pulse.manage): a rule writes DNS, and splitting "who configures
# rules" from "who configures checks" would be a sham, since the latter can quietly flip the former.
# All substantive validation lives in the core (functions.pm); here only rights, body shape and audit.
# ============================================================================
sub _pulse_ok { my ($self) = @_; return $self->_cap_ok('pulse.manage'); }

# GET /pulse: everything for the page in one request. Lists include relation ids, so edit forms need no
# second request.
sub _pulse_all {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($testers, $e1) = pulse_testers_all(); return _inv_fail($e1) if $e1;
    my ($groups,  $e2) = pulse_groups_all();  return _inv_fail($e2) if $e2;
    my ($checks,  $e3) = pulse_checks_all();  return _inv_fail($e3) if $e3;
    my ($rules,   $e4) = pulse_rules_all();   return _inv_fail($e4) if $e4;
    # Zones are included for the same reason as on the page: a refresh after an edit replaces data WHOLESALE,
    # and without them the "+ Add rule" form would think there is nowhere to write.
    my ($zones,   $e5) = pulse_zones_writable(); return _inv_fail($e5) if $e5;
    return API::Response->ok({ testers => $testers, groups => $groups, checks => $checks,
                               rules => $rules, zones => $zones,
                               server => pulse_server_hint(),
                               # New-check defaults ship with the page: the numbers belong to settings, and
                               # the browser must not keep a second copy.
                               check_defaults => pulse_check_defaults(),
                               rr_types => [ @functions::PULSE_RR_TYPES ] });
}

# ---- Testers ----
my @PULSE_TESTER_FIELDS = qw(name location enabled confirm_max_age_seconds);
# An enrolment is approved by a HUMAN, who names the agent at that point; until then only the agent knows itself.
sub _pulse_tester_approve {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name location confirm_max_age_seconds)]); return $bad if $bad;
    my ($ok, $err) = pulse_tester_save($id, $b, 1); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_tester_approve', 'pulse_tester', $id, { after => $b });
    return API::Response->ok({ approved => JSON::true });
}
sub _pulse_tester_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body(\@PULSE_TESTER_FIELDS); return $bad if $bad;
    my ($ok, $err) = pulse_tester_save($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_tester_update', 'pulse_tester', $id, { after => $b });
    return API::Response->ok({ id => $id + 0 });
}
sub _pulse_tester_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $label = audit_target_label('pulse_tester', $id);   # name snapshot BEFORE deletion
    my ($r, $err) = pulse_tester_delete($id); return _inv_fail($err) if $err;
    # affected_rules: rules whose conditions the deletion removed (FK CASCADE). That is a consequence the user
    # must see in the audit log and the response. detail only when non-empty: an empty one is noise.
    my @hit = @{ $r->{affected_rules} || [] };
    _inv_audit($u, 'pulse_tester_delete', 'pulse_tester', $id,
               { label => $label, (@hit ? (detail => { affected_rules => join(', ', @hit) }) : ()) });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0,
                               affected_rules => ($r->{affected_rules} || []) });
}
# The enrolment key is shared and replaced as a whole. Already approved agents keep working: each has its
# own key and no longer needs the enrolment one.
sub _pulse_enroll_key_new {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($key, $err) = pulse_enroll_key_new(); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_enroll_key_new', 'pulse_server', 1);
    return API::Response->ok({ server => pulse_server_hint() });
}
# Address agents use to find Pulse. It also goes into the ready agent config, so it is edited where that
# config is shown.
sub _pulse_server_address {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(address)]); return $bad if $bad;
    my ($ok, $err) = pulse_server_address_set($b->{address}); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_server_address_set', 'pulse_server', 1, { after => { address => $b->{address} } });
    return API::Response->ok({ server => pulse_server_hint() });
}

# ---- Tester groups ----
sub _pulse_group_create {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)]); return $bad if $bad;
    my ($id, $err) = pulse_group_save(undef, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_group_create', 'pulse_group', $id, { after => $b });
    return API::Response->created({ id => $id + 0 });
}
sub _pulse_group_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(name description)]); return $bad if $bad;
    my ($ok, $err) = pulse_group_save($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_group_update', 'pulse_group', $id, { after => $b });
    return API::Response->ok({ id => $id + 0 });
}
sub _pulse_group_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $label = audit_target_label('pulse_group', $id);
    my ($ok, $err) = pulse_group_delete($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_group_delete', 'pulse_group', $id, { label => $label });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}
# Group membership changes WHO runs its checks: pairs appear and disappear, and their state rows with them.
# The job version is NOT bumped: it is about the measurement, which stays the same.
sub _pulse_group_members {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(testers)]); return $bad if $bad;
    return API::Response->bad_request('testers must be an array') unless ref $b->{testers} eq 'ARRAY';
    my ($ok, $err) = pulse_group_members_set($id, $b->{testers}); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_group_members_set', 'pulse_group', $id,
               { after => { testers => scalar @{ $b->{testers} } } });
    return API::Response->ok({ id => $id + 0 });
}

# ---- Checks ----
my @PULSE_CHECK_FIELDS = qw(name kind target_ip port interval_seconds timeout_ms
                            probes_per_run ok_probes_required fail_threshold ok_threshold enabled);
# State history: bars for the chosen window. Read-only; the window comes as a parameter.
sub _pulse_history {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $q = $self->{cgi};
    my $win   = ($q && defined $q->param('window')) ? $q->param('window') : '1d';
    my $check = ($q && defined $q->param('check') && length $q->param('check')) ? $q->param('check') : undef;
    my ($h, $err) = pulse_history({ window => $win, (defined $check ? (check_id => $check) : ()) });
    return _inv_fail($err) if $err;
    return API::Response->ok($h);
}
# History of ONE record: what Pulse published and why. Opened from the record's own history dialog, next to
# its edit history: the question is the same, "why is it like this".
sub _pulse_rrset_history {
    my ($self, $zid) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $q = $self->{cgi};
    my $win = ($q && defined $q->param('window')) ? $q->param('window') : '1d';
    my ($h, $err) = pulse_rrset_history($zid, ($q ? $q->param('name') : undef),
                                        ($q ? $q->param('type') : undef), $win);
    return _inv_fail($err) if $err;
    return API::Response->ok($h);
}
# Slow sweep history for one RRset: one bar per address, clipped to the time the address actually belonged
# to this record.
#
# The capability here DIFFERS from the rest of Pulse: "does the address answer" is observing the zone, not
# configuring switching. Whoever can see the zone can see its availability, but still may not configure Pulse.
sub _pulse_rrset_sweep {
    my ($self, $zid) = @_;
    my $user = _current_user($self);
    return API::Response->unauthorized('Authentication required') unless $user;
    my $zone = pdns_get_domain($zid) or return API::Response->not_found('Zone not found');
    return API::Response->forbidden("No access to zone '$zone->{name}'")
        if effective_zone_access($user, $zone) eq 'none';
    my $q = $self->{cgi};
    my $win = ($q && defined $q->param('window')) ? $q->param('window') : '1d';
    my ($h, $err) = pulse_sweep_rrset_history($zid, ($q ? $q->param('name') : undef),
                                              ($q ? $q->param('type') : undef), $win);
    return _inv_fail($err) if $err;
    return API::Response->ok($h);
}
# Sweep parameters are edited in the panel (as promised in §7): a number that affects behaviour needs a
# visible owner, not a row that appeared on its own.
sub _pulse_settings_set {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body(pulse_policy_fields(), patch => 1); return $bad if $bad;
    my ($saved, $err) = pulse_policy_set($b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_settings_update', 'pulse_settings', 0, { after => $saved });
    return API::Response->ok($saved);
}
sub _pulse_check_create {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body(\@PULSE_CHECK_FIELDS); return $bad if $bad;
    my ($id, $err) = pulse_check_save(undef, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_check_create', 'pulse_check', $id, { after => $b });
    return API::Response->created({ id => $id + 0 });
}
sub _pulse_check_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body(\@PULSE_CHECK_FIELDS); return $bad if $bad;
    my ($ok, $err) = pulse_check_save($id, $b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_check_update', 'pulse_check', $id, { after => $b });
    return API::Response->ok({ id => $id + 0 });
}
sub _pulse_check_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $label = audit_target_label('pulse_check', $id);   # name snapshot BEFORE deletion
    my ($r, $err) = pulse_check_delete($id); return _inv_fail($err) if $err;
    # As with testers: deletion cascades away rule conditions, a consequence the user must see in the
    # response and the audit log. detail only when non-empty.
    my @hit = @{ $r->{affected_rules} || [] };
    _inv_audit($u, 'pulse_check_delete', 'pulse_check', $id,
               { label => $label, (@hit ? (detail => { affected_rules => join(', ', @hit) }) : ()) });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0,
                               affected_rules => ($r->{affected_rules} || []) });
}
sub _pulse_check_groups {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    # "Who runs it" is groups AND named agents. agents is optional: without it named assignments stay as they
    # were, so older clients don't wipe them.
    my ($b, $bad) = _strict_body([qw(groups agents)]); return $bad if $bad;
    return API::Response->bad_request('groups must be an array') unless ref $b->{groups} eq 'ARRAY';
    return API::Response->bad_request('agents must be an array')
        if exists $b->{agents} && ref $b->{agents} ne 'ARRAY';
    my ($ok, $err) = pulse_check_groups_set($id, $b->{groups}, $b->{agents}); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_check_groups_set', 'pulse_check', $id,
               { after => { groups => scalar @{ $b->{groups} },
                            agents => (exists $b->{agents} ? scalar @{ $b->{agents} } : undef) } });
    return API::Response->ok({ id => $id + 0 });
}

# ---- Rules ----
# Rule candidates: single-address sets nobody manages yet. The right to manage a record is the right to see
# which records can be taken.
sub _pulse_zone_records {
    my ($self, $zid) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($rows, $err) = pulse_rule_candidates($zid); return _inv_fail($err) if $err;
    return API::Response->ok({ records => $rows });
}
# Pulse settings for an RRset: existing or a DRAFT. Opening it does not create anything.
sub _pulse_rrset {
    my ($self, $zid) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $q = $self->{cgi};
    my ($r, $err) = pulse_rrset_draft($zid, scalar($q->param('name')), scalar($q->param('type')));
    return _inv_fail($err) if $err;
    return API::Response->ok({ rule => $r });
}

sub _pulse_rule_get {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($r, $err) = pulse_rule_get($id); return _inv_fail($err) if $err;
    return API::Response->ok({ rule => $r });
}
sub _pulse_rule_create {
    my ($self) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(domain_id rr_name rr_type default_hold_seconds schedule_tz)]);
    return $bad if $bad;
    my ($id, $err) = pulse_rule_create($b); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_rule_create', 'pulse_rule', $id,
               { after => { rr_name => $b->{rr_name}, rr_type => $b->{rr_type} } });
    return API::Response->created({ id => $id + 0 });
}
sub _pulse_rule_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(default_hold_seconds schedule_tz enabled)], patch => 1);
    return $bad if $bad;
    my ($ok, $err) = pulse_rule_update($id, $b); return _inv_fail($err) if $err;
    # Enable and disable are separate audit actions: from that moment the rule moves DNS.
    my $action = exists $b->{enabled} && scalar(keys %$b) == 1
        ? ($b->{enabled} ? 'pulse_rule_enabled' : 'pulse_rule_disabled') : 'pulse_rule_update';
    _inv_audit($u, $action, 'pulse_rule', $id, { after => $b });
    return API::Response->ok({ id => $id + 0 });
}
sub _pulse_rule_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my $label = audit_target_label('pulse_rule', $id);
    my ($ok, $err) = pulse_rule_delete($id); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_rule_delete', 'pulse_rule', $id, { label => $label });
    return API::Response->ok({ deleted => JSON::true, id => $id + 0 });
}
# Copying a setup to other records is ONE operation, not a dozen browser requests: the core decides what is
# copied, and the audit log gets one event instead of a scatter of identical ones.
sub _pulse_rule_clone {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(targets)]); return $bad if $bad;
    return API::Response->bad_request('targets must be an array') unless ref $b->{targets} eq 'ARRAY';
    my ($r, $err) = pulse_rule_clone_to($id, $b->{targets}); return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_rule_clone', 'pulse_rule', $id,
               { detail => { copied => join(', ', @{ $r->{done} }) || 'none',
                             failed => scalar @{ $r->{failed} } } });
    return API::Response->ok($r);
}
# Branches arrive WHOLE and in on-screen order: the order is the behaviour.
sub _pulse_rule_branches {
    my ($self, $id) = @_; my ($u, $deny) = $self->_pulse_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(branches default_hold_seconds)]); return $bad if $bad;
    return API::Response->bad_request('branches must be an array') unless ref $b->{branches} eq 'ARRAY';
    # The form is saved whole: the fallback set's hold time arrives here too, not as a separate edit.
    my ($ok, $err) = pulse_rule_branches_set($id, $b->{branches}, $b->{default_hold_seconds});
    return _inv_fail($err) if $err;
    _inv_audit($u, 'pulse_rule_branches_set', 'pulse_rule', $id,
               { after => { branches => scalar @{ $b->{branches} } } });
    my ($r, $ge) = pulse_rule_get($id); return _inv_fail($ge) if $ge;
    return API::Response->ok({ rule => $r });
}

# ---- External access (Settings -> External access), users.manage; changes are audited. ----
sub _openapi { return API::Response->json('200 OK', API::OpenAPI::spec()); }
sub _external_get {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($tokens, $e) = api_token_list(); return _inv_fail($e) if $e;
    (my $users, $e) = users_all(); return _inv_fail($e) if $e;
    (my $oidc, $e) = oidc_provider_list(); return _inv_fail($e) if $e;
    return API::Response->ok({ settings => external_settings(), tokens => $tokens, oidc => $oidc,
                               users => [ map { { id => $_->{id} + 0, username => $_->{username} } } grep { $_->{is_active} } @$users ] });
}
sub _external_set {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(mcp_http anonymous_read mcp_readonly)], patch => 1); return $bad if $bad;
    my ($s, $e) = external_settings_set($b); return _inv_fail($e) if $e;
    _inv_audit($u, 'external_settings_update', 'settings', 'external', { label => 'External access', after => $b });
    return API::Response->ok($s);
}
sub _token_create {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body([qw(user_id name expires_at)]); return $bad if $bad;
    my ($t, $e) = api_token_create($b); return _inv_fail($e) if $e;
    _inv_audit($u, 'api_token_create', 'api_token', $t->{id}, { label => "$t->{username} · $t->{name}",
               after => { user => $t->{username}, name => $t->{name}, expires_at => $b->{expires_at} } });
    return API::Response->created($t);
}
sub _token_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $t = api_token_get($id) or return API::Response->not_found('Token not found');
    my ($b, $bad) = _strict_body([qw(name enabled expires_at)], patch => 1); return $bad if $bad;
    my ($ok, $e) = api_token_update($id, $b); return _inv_fail($e) if $e;
    _inv_audit($u, 'api_token_update', 'api_token', $id, { label => "$t->{username} · $t->{name}", after => $b });
    return API::Response->ok({ id => $id + 0 });
}
my @OIDC_FIELDS = qw(name issuer audience username_claim enabled);
sub _oidc_create {
    my ($self) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my ($b, $bad) = _strict_body(\@OIDC_FIELDS); return $bad if $bad;
    my ($id, $e) = oidc_provider_create($b); return _inv_fail($e) if $e;
    _inv_audit($u, 'oidc_provider_create', 'oidc_provider', $id, { label => $b->{name}, after => $b });
    return API::Response->created({ id => $id });
}
sub _oidc_update {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $p = oidc_provider_get($id) or return API::Response->not_found('Provider not found');
    my ($b, $bad) = _strict_body(\@OIDC_FIELDS, patch => 1); return $bad if $bad;
    my ($ok, $e) = oidc_provider_update($id, $b); return _inv_fail($e) if $e;
    _inv_audit($u, 'oidc_provider_update', 'oidc_provider', $id, { label => ($b->{name} // $p->{name}), after => $b });
    return API::Response->ok({ id => $id + 0 });
}
sub _oidc_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $p = oidc_provider_get($id) or return API::Response->not_found('Provider not found');
    my ($ok, $e) = oidc_provider_delete($id); return _inv_fail($e) if $e;
    _inv_audit($u, 'oidc_provider_delete', 'oidc_provider', $id, { label => $p->{name}, before => { name => $p->{name}, issuer => $p->{issuer} } });
    return API::Response->ok({ deleted => 1 });
}
sub _token_delete {
    my ($self, $id) = @_; my ($u, $deny) = $self->_users_ok; return $deny if $deny;
    my $t = api_token_get($id) or return API::Response->not_found('Token not found');
    my ($ok, $e) = api_token_delete($id); return _inv_fail($e) if $e;
    _inv_audit($u, 'api_token_delete', 'api_token', $id, { label => "$t->{username} · $t->{name}", before => { name => $t->{name} } });
    return API::Response->ok({ deleted => 1 });
}

1;
