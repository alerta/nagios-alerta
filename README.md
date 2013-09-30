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
    $ make
    $ sudo cp src/alerta-neb.o /usr/lib/nagios3
    $ sudo service nagios3 restart

Alerts
------

nagios.cfg
```
broker_module=/usr/lib/nagios3/alerta-neb.o http://localhost:8080
```

To enable debug mode:
```
broker_module=/usr/lib/nagios3/alerta-neb.o http://localhost:8080 debug=1
```

Heartbeats
----------

1. define a heartbeat command
```
define command{
        command_name    check_heartbeat
        command_line    /usr/lib/nagios/plugins/check_dummy 0
}
```

2. define a hostgroup for nagios servers
```
define hostgroup {
        hostgroup_name  nagios-servers
                alias           Nagios servers
                members         localhost
}
```

3. define a Heartbeat service check to execute every minute:
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
