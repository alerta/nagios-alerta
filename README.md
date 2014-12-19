Nagios-to-Alerta Gateway
========================

Consolidate Nagios alerts from across multiple sites into a single "at-a-glance" console.

Transform this ...

![nagios](/docs/images/nagios.png?raw=true)

Into this ...

![alerta](/docs/images/alerta.png?raw=true)

Installation
------------

    $ git clone https://github.com/alerta/nagios3-alerta.git
    $ cd nagios3-alerta
    $ make
    $ sudo make install
    $ sudo service nagios3 restart

Alerts
------

To forward host and service check results to Alerta, modify `/etc/nagios3/nagios.cfg` as follows:
```
broker_module=/usr/lib/nagios3/alerta-neb.o http://localhost:8080
```

To provide the API key if authentication is enabled on the alerta server:
```
broker_module=/usr/lib/nagios3/alerta-neb.o http://localhost:8080 key=INSERT_API_KEY_HERE
```

And to enable debug mode:
```
broker_module=/usr/lib/nagios3/alerta-neb.o http://localhost:8080 debug=1
```

Heartbeats
----------

To configure the Nagios server to send regular heartbeats to Alerta to ensure that Nagios and the event broker are still forwarding alerts configure a dummy service check as follows:

1. Define a heartbeat command and add it to `/etc/nagios3/commands.cfg`:
```
define command{
        command_name    check_heartbeat
        command_line    /usr/lib/nagios/plugins/check_dummy 0
}
```

2. Define a hostgroup for the Nagios servers that have the Alerta event broker installed and add it to `/etc/nagios3/conf.d/hostgroups_nagios2.cfg`:
```
define hostgroup {
        hostgroup_name  nagios-servers
                alias           Nagios servers
                members         localhost
}
```

3. Define a Heartbeat service check to execute every minute and add it to `/etc/nagios3/conf.d/services_nagios2.cfg`:
```
define service {
        hostgroup_name                  nagios-servers
        service_description             Heartbeat
        check_command                   check_heartbeat
        use                             generic-service
        notification_interval           0 ; set > 0 if you want to be renotified
        normal_check_interval           1
}
```

License
-------

Copyright (c) 2013 Nick Satterly. Available under the MIT License.
