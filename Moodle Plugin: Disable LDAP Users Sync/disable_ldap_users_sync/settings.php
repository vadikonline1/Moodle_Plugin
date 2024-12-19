<?php
defined('MOODLE_INTERNAL') || die();


if ($hassiteconfig) {

    $settings = new admin_settingpage('local_disable_ldap_users_sync', get_string('pluginname', 'local_disable_ldap_users_sync'));


    $settings->add(new admin_setting_configcheckbox(
        'local_disable_ldap_users_sync/enabled',
        get_string('enabled', 'local_disable_ldap_users_sync'),
        get_string('enabled_desc', 'local_disable_ldap_users_sync'),
        0,
        PARAM_BOOL
    ));

	$settings->add(new admin_setting_configtext(
        'local_disable_ldap_users_sync/logfile',
        get_string('logfile', 'local_disable_ldap_users_sync'),
        get_string('logfile_desc', 'local_disable_ldap_users_sync'),
        ''
    ));


    $ADMIN->add('localplugins', $settings);
}
