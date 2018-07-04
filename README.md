## aws-greengrass-group-setup

[![PyPI](https://img.shields.io/pypi/l/gg-group-setup.svg)]() [![PyPI](https://img.shields.io/pypi/v/gg-group-setup.svg)]()

Greengrass **`gg_group_setup`** is an example file-driven approach to the creation 
of an entire AWS Greengrass group.

Usually the following discrete steps are necessary to setup and deploy a Greengrass group.

- [`create_thing`](http://docs.aws.amazon.com/iot/latest/developerguide/thing-registry.html)
- [`create_core_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_core_definition)
- [`create_device_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_device_definition)
- [`create_function_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_function_definition)
- [`create_logger_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_logger_definition)
- [`create_subscription_definition`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_subscription_definition)
- [`create_deployment`](https://boto3.readthedocs.io/en/latest/reference/services/greengrass.html#Greengrass.Client.create_deployment)

**`gg_group_setup`** provides functioning example code of how a Greengrass Group is 
created. It also provides a:
- `gg_group_setup` config file parser `GroupConfigFile` which can be sub-classed
- file-driven command line interface encapsulated in the `GroupComnands` class
    - The `GroupCommands` class is also an example implementation of the steps 
    necessary to create a Greengrass Group. 
- `GroupType` which can be sub-classed for more complex `GroupCommands` scenarios

`gg_group_setup` includes multiple commands: 
`create`, `deploy`, `create-core`, `create-devices`, `clean-core`, 
`clean-devices`, `clean-file`, and `clean-all`.

After installation you can use these commands from the Command Line Interface, or 
you can use them from within a program via the `GroupCommands` class. 

### Installation

The quickest way to get `gg_group_setup` is to install the latest stable version via `pip`.

    pip install gg-group-setup
    
After installation, for command line help type:

    gg_group_setup create -- --help
    gg_group_setup deploy -- --help
    gg_group_setup create-core -- --help
    gg_group_setup create-devices -- --help
    gg_group_setup clean-core -- --help
    gg_group_setup clean-devices -- --help
    gg_group_setup clean-file -- --help
    gg_group_setup clean-all -- --help
    gg_group_setup associate_devices -- --help

### Quick Start

The high-level process to create a Greengrass group using `gg_group_setup` is as
follows:

1. Execute `$ gg_group_setup create-core <thing_name> <config_file>` -- to create a Greengrass Core named `thing_name`
1. Execute `$ gg_group_setup create-devices '[<device_thing_name_01>,<device_thing_name_02,...]' <config_file>`
  -- to create things for use as devices in your Greengrass Group.
1. [Create](http://docs.aws.amazon.com/lambda/latest/dg/with-scheduledevents-example.html) 
and [alias](http://docs.aws.amazon.com/lambda/latest/dg/aliases-intro.html) your 
Lambda function(s) 
1. Update the group `<config_file>`. Example: `cfg.json`
    1. update the `lambda_functions` section
        1. In the `lambda_functions` section of the configuration, replace `<function_name>` 
        with the name of the Lambda function configured and aliased previously. Then for 
        that function enter the `arn` and `arn_qualifier` of the function.
            ```json
            "lambda_functions": {
              "<function_name>": {
                "arn": "<lambda_ARN>",
                "arn_qualifier": "<alias>"
              }
            },
            ```
        
        1. For example, if the Lambda function is created in `us-west-2`, named 
        `MyFirstGreengrassLambda`, and the alias named `dev` pointing to version `1`, 
        the `lambda_functions` section would contain these values.
            ```json
            "lambda_functions": {
              "MyFirstGreengrassLambda": {
                "arn": "arn:aws:lambda:us-west-2:<account_id>:function:MyFirstGreengrassLambda:dev",
                "arn_qualifier": "dev"
              }
            },
            ```
        
            - If you need more than one function in the group named 
            `MyFirstGreengrassLambda` and `MockDeviceLambda`, the `lambda_functions` section would 
            contain these values.
                ```json
                "lambda_functions": {
                  "MyFirstGreengrassLambda": {
                    "arn": "arn:aws:lambda:us-west-2:<account_id>:function:MyFirstGreengrassLambda:dev",
                    "arn_qualifier": "dev"
                  },
                  "MockDeviceLambda": {
                    "arn": "arn:aws:lambda:us-west-2:<account_id>:function:MockDeviceLambda:dev",
                    "arn_qualifier": "dev"
                  }
                },
                ```
    1. update the `subscriptions` section
        1. the subscriptions section should reflect the topics the Lambda 
        functions and devices in the group use to communicate with each other and 
        the cloud. 
        For example, the `MockDevice` Lambda function expects to use the following subscriptions:
            ```json
            "subscriptions": {
              "errors": "/errors",
              "telemetry": "/telemetry"
            }
            ```
1. Download the Greengrass software and follow [these instructions](http://docs.aws.amazon.com/greengrass/latest/userguide/extract-distributable.html) 
to extract the software onto the Greengrass core.
1. [Install](http://docs.aws.amazon.com/greengrass/latest/userguide/install-core-certs.html) 
the Greengrass core's certificates onto the core device
1. [Start](http://docs.aws.amazon.com/greengrass/latest/userguide/start-core.html) 
your Greengrass core
1. Execute `$ gg_group_setup create <group_type> <config_file>` -- to create the Greengrass group
1. Execute `$ gg_group_setup deploy <config_file>` -- to deploy the Greengrass group

> Note: **gg_group_setup** also includes a Mock Device Lambda function you can use to 
get started. 

### Using `gg_group_setup` as a Library

After the **Quick Start,** you will probably want to configure your own unique Greengrass 
group with its own Lambda functions, devices, and subscription topology. To do 
this you will need to implement a sub-class of `GroupType`. 
 
In the `gg_group_setup` folder you will see an example `mock_device` Lambda function 
and a `mock_group`. 

After implementing a sub-class of `GroupType` called `CustomGroupType`, update 
the group `<config_file>` to reflect the custom group. The custom group can then 
be used in code as follows:
```python
    config_file = "<filename>"  # filename of the group's <config_file>
    group_name = "<group_name>"  # if `None`, the group_type value will be used
    region = "<aws_region>"  # AWS region in which the group will be created
 
    gc = GroupCommands(group_types={
        CustomGroupType.CUSTOM_TYPE: CustomGroupType
    })
    gc.create(
        config_file, group_type=CustomGroupType.CUSTOM_TYPE, 
        group_name=group_name, region=region
    )
```

### Entering an account_id
If you add your account ID to the `config_file` manually before running any 
commands`gg_group_setup` will use the account ID to make a notch more 
restrictive Core and Device policies. Specifically, if you enter a value here:
```json
  ...
  "misc": {
    "account_id": "<account_id_here>",
    "iot_endpoint": ""
  },...
``` 
These [instructions](http://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html) 
show you how to find your AWS account ID. 

### Using the `config_file` manually

Although the helper commands `create-core` and `create-devices` will create 
things and store the proper information in the given `config_file`, you can also 
ignore those commands if you want to enter all the information manually. 
The `create`, `deploy`, and `clean-all` Greengrass group commands will use the 
`config_file` information as stored. 

### Projects using `gg_group_setup`
The [`aws-greengrass-mini-fulfillment`](https://github.com/awslabs/aws-greengrass-mini-fulfillment) 
repository creates and uses pretty complex custom [group types](https://github.com/awslabs/aws-greengrass-mini-fulfillment/blob/master/groups/group_setup.py).