<?php
namespace local_disable_ldap_users_sync\task;

defined('MOODLE_INTERNAL') || die();

use core\task\scheduled_task;
require_once($CFG->dirroot . '/local/disable_ldap_users_sync/lib.php');
class sync_task extends scheduled_task {
    
    public function get_name() {
        return get_string('task_sync_ldap_users', 'local_disable_ldap_users_sync');
    }

    public function execute() {
        mtrace("Start syncing LDAP users to disable them...");
		local_disable_ldap_users_sync_execute_for_all_users();
		mtrace("LDAP users sync completed.");
}
}