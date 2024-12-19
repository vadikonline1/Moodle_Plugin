<?php
defined('MOODLE_INTERNAL') || die();

$tasks = array(
    array(
        'classname' => 'local_disable_ldap_users_sync\task\sync_task',
        'blocking' => 0,
        'minute' => '*',
        'hour' => '*/23',
        'day' => '*',
        'month' => '*',
        'dayofweek' => '*',
    ),
);
