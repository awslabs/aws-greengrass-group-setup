aws-greengrass-group-setup
--------------------------

Greengrass **`gg_group_setup`** is an example file-driven approach to the creation 
of an entire AWS Greengrass group.

Usually the following discrete steps are necessary to setup and deploy a Greengrass group.

- [`create_core_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_core_definition)
- [`create_device_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_device_definition)
- [`create_function_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_function_definition)
- [`create_logger_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_logger_definition)
- [`create_subscription_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_subscription_definition)
- [`create_deployment`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_deployment)

**`gg_group_setup`** provides functioning example code of how a Greengrass Group is 
created. It also provides a:
- `gg_group_setup` config file parser `GroupConfigFile` which can be sub-classed
- file-driven command line interface

The file-driven command line demonstrates the steps necessary to create 
a Greengrass Group. The command line includes four commands: 
`create`, `deploy`, `clean_all`, and `clean_file`.

Installation
------------

The quickest way to get `gg_group_setup` is to install the latest stable version via `pip`.

    pip install gg_group_setup
    
..or of course you can clone this repository and execute `python setup.py install .`

After installation, for help type:

    gg_group_setup create -- --help
    gg_group_setup deploy -- --help
    gg_group_setup clean_all -- --help
    gg_group_setup clean_file -- --help

Quick Start
-----------
At a high-level the process to create a Greengrass group using `gg_group_setup` is as follows:

    ..make your Things
    ..create and alias your Lambda ƒ
    ..update config file
    $ gg_group_setup create <config_file>

The command line tool can be used once the AWS IoT Things are [created and attached](http://docs.aws.amazon.com/iot/latest/developerguide/thing-registry.html) 
to a [certificate](http://docs.aws.amazon.com/iot/latest/developerguide/managing-device-certs.html) 
and AWS Lambda functions are [created](http://docs.aws.amazon.com/lambda/latest/dg/with-scheduledevents-example.html) 
and [aliased](http://docs.aws.amazon.com/lambda/latest/dg/aliases-intro.html) 
in the AWS Platform.

> Note: **gg_group_setup** also includes a Mock Device Lambda function you can use to 
get started. 

