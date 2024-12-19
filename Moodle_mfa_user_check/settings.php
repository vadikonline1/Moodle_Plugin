<?php
defined('MOODLE_INTERNAL') || die();

if ($hassiteconfig) {
    $settings = new admin_settingpage('local_mfa_user_check', get_string('pluginname', 'local_mfa_user_check'));
    $mfa_enabled_setting = $DB->get_record('config_plugins', array('plugin' => 'tool_mfa', 'name' => 'enabled'));
    $status_mfa = (isset($mfa_enabled_setting->value) && $mfa_enabled_setting->value == '1') 
        ? get_string('tool_mfa_active', 'local_mfa_user_check') 
        : get_string('tool_mfa_inactive', 'local_mfa_user_check');
    
    $settings->add(new admin_setting_description(
        'tool_mfa_status',
        get_string('tool_mfa_status', 'local_mfa_user_check'),
        $status_mfa . '<hr>'
    ));

    if ($mfa_enabled_setting->value == '1') {
        $settings->add(new admin_setting_configcheckbox(
            'local_mfa_user_check/enabled',
            get_string('pluginenabled', 'local_mfa_user_check'),
            get_string('pluginenabled_desc', 'local_mfa_user_check'),
            0
        ));
		// Setarea pentru Whitelist_Users_ID
		$settings->add(new admin_setting_configtext(
			'local_mfa_user_check/whitelist_users_id',
			get_string('whitelist_users_id', 'local_mfa_user_check'),
			get_string('whitelist_users_id_desc', 'local_mfa_user_check'),
			'2', // ID implicit
			PARAM_TEXT
		));
    } else {
        set_config('enabled', 0, 'local_mfa_user_check');
    }
    $ADMIN->add('localplugins', $settings);
}
