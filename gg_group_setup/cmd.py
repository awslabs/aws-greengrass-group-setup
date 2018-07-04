#!/usr/bin/env python

# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License is
# located at
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

import os
import fire
import json
import boto3
import logging
from boto3.session import Session
from botocore.exceptions import ClientError
from gg_group_setup import GroupConfigFile

logging.basicConfig(format='%(asctime)s|%(name)-8s|%(levelname)s: %(message)s',
                    level=logging.DEBUG)


def _get_iot_session(region, profile_name=None):
    if profile_name is None:
        logging.debug("loading AWS IoT client using 'default' AWS CLI profile")
        return Session(region_name=region).client('iot')

    logging.debug("loading AWS IoT client using '{0}' AWS CLI profile".format(
        profile_name))
    return Session(
        region_name=region,
        profile_name=profile_name).client('iot')


def _get_gg_session(region, profile_name=None):
    if profile_name is None:
        logging.debug(
            "loading AWS Greengrass client using 'default' AWS CLI profile")
        return Session(region_name=region).client('greengrass')

    logging.debug(
        "loading AWS Greengrass client using '{0}' AWS CLI profile".format(
            profile_name))
    return Session(
        region_name=region,
        profile_name=profile_name).client('greengrass')


class GroupCommands(object):
    def __init__(self, group_types=None, account_id=None,
                 region='us-west-2'):
        """
        Commands used to create a Greengrass group.

        Specifically the given group types can be used to `create` and `deploy`
        a group as well as `clean_all` provisioned artifacts of a group, or
        `clean_file` to only clean the local config file.

        :param group_types: dict containing custom `GroupType` classes for use
                            by this class' commands.

        """
        super(GroupCommands, self).__init__()
        self.group_types = group_types
        self._region = region
        self._account_id = account_id

    def create(self, group_type, config_file, group_name=None,
               region=None, profile_name=None):
        """
        Create a Greengrass group in the given region.

        :param group_type: the type of group to create. Must match a `key` in
            the `group_types` dict
        :param config_file: config file of the group to create
        :param group_name: the name of the group. If no name is given, then
            group_type will be used.
        :param region: the region in which to create the new group.
            [default: us-west-2]
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        logging.info("[begin] create command using group_types:{0}".format(
            self.group_types))

        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh() is False:
            raise ValueError(
                "Config file already tracking previously created group"
            )

        if group_type not in self.group_types.keys():
            raise ValueError("Can only create {0} groups.".format(
                self.group_types)
            )

        if region is None:
            region = self._region

        # create an instance of the requested group type that uses the given
        # config file and region
        gt = self.group_types[group_type](config=config, region=region)

        # get and store the account's IoT endpoint for future use
        ep = _get_iot_session(region=region).describe_endpoint()
        misc = config['misc']
        misc['iot_endpoint'] = ep['endpointAddress']
        config['misc'] = misc

        # Create a Group
        logging.info("[begin] Creating a Greengrass Group")
        if group_name is None:
            group_name = group_type

        gg_client = _get_gg_session(region=region, profile_name=profile_name)

        group_info = gg_client.create_group(Name="{0}".format(group_name))
        config['group'] = {"id": group_info['Id']}

        # setup the policies and roles
        gt.create_and_attach_thing_policy()
        gt.create_and_attach_iam_role()

        cl_arn = self._create_core_definition(
            gg_client=gg_client, group_type=gt,
            config=config, group_name=group_name
        )
        dl_arn = self._create_device_definition(
            gg_client=gg_client, group_type=gt,
            config=config, group_name=group_name
        )
        lv_arn = self._create_function_definition(
            gg_client=gg_client, group_type=gt,
            config=config
        )
        log_arn = self._create_logger_definition(
            gg_client=gg_client, group_type=gt,
            config=config
        )
        sub_arn = self._create_subscription_definition(
            gg_client=gg_client, group_type=gt,
            config=config
        )

        logging.info(
            'Group details, core_def:{0} device_def:{1} func_def:{2} '
            'logger_def:{3} subs_def:{4}'.format(
                cl_arn, dl_arn, lv_arn, log_arn, sub_arn)
        )

        # Add all the constituent parts to the Greengrass Group
        group_args = {'GroupId': group_info['Id']}
        if cl_arn:
            group_args['CoreDefinitionVersionArn'] = cl_arn
        if dl_arn:
            group_args['DeviceDefinitionVersionArn'] = dl_arn
        if lv_arn:
            group_args['FunctionDefinitionVersionArn'] = lv_arn
        if log_arn:
            group_args['LoggerDefinitionVersionArn'] = log_arn
        if sub_arn:
            group_args['SubscriptionDefinitionVersionArn'] = sub_arn
        grp = gg_client.create_group_version(
            **group_args
        )

        # store info about the provisioned artifacts into the local config file
        config['group'] = {
            "id": group_info['Id'],
            "version_arn": grp['Arn'],
            "version": grp['Version'],
            "name": group_name
        }
        logging.info(
            "[end] Created Greengrass Group {0}".format(group_info['Id']))

    @staticmethod
    def _create_core_definition(gg_client, group_type, config, group_name):
        core_def = group_type.get_core_definition(config=config)
        core_def_id = config['core_def']['id']
        if core_def_id is None or len(core_def_id) == 0:
            cd = gg_client.create_core_definition(
                Name="{0}_core_def".format(group_name)
            )
            core_def_id = cd['Id']
            cdv = gg_client.create_core_definition_version(
                CoreDefinitionId=core_def_id,
                Cores=core_def
            )
            cd_arn = cdv['Arn']
            logging.info("Created Core definition ARN:{0}".format(cd_arn))
            config['core_def'] = {'id': core_def_id, 'version_arn': cd_arn}
            logging.info("CoreDefinitionId: {0}".format(core_def_id))
            return cd_arn
        else:
            logging.info(
                "CoreDefinition already exists:{0}".format(core_def_id))

    @staticmethod
    def _create_device_definition(gg_client, group_type, config, group_name):
        device_def = group_type.get_device_definition(config=config)
        device_def_id = config['device_def']['id']
        if device_def is None:
            logging.warning("No DeviceDefinition exists in GroupType:{0}".format(
                group_type.type_name)
            )
            return

        if device_def_id is None or len(device_def_id) == 0:
            dl = gg_client.create_device_definition(
                Name="{0}_device_def".format(group_name))
            device_def_id = dl['Id']
            dlv = gg_client.create_device_definition_version(
                DeviceDefinitionId=device_def_id,
                Devices=device_def
            )
            dl_arn = dlv['Arn']
            logging.info("Created Device definition ARN:{0}".format(dl_arn))
            config['device_def'] = {'id': dl['Id'], 'version_arn': dl_arn}
            logging.info("DeviceDefinitionId: {0}".format(device_def_id))
            return dl_arn

        else:
            logging.info("DeviceDefinition already exists:{0}".format(
                device_def_id)
            )
            return

    @staticmethod
    def _create_function_definition(gg_client, group_type, config, region=None):
        # Add latest version of Lambda functions to a Function definition
        aws = boto3.client('lambda', region_name=region)
        latest_funcs = dict()
        func_definition = []
        # first determine the latest versions of configured Lambda functions
        for key in config['lambda_functions']:
            lambda_name = key
            try:
                a = aws.list_aliases(FunctionName=lambda_name)
                # assume only one Alias associated with the Lambda function
                alias_arn = a['Aliases'][0]['AliasArn']
                logging.info("function {0}, found aliases: {1}".format(
                    lambda_name, a)
                )

                # get the function pointed to by the alias
                q = config['lambda_functions'][lambda_name]['arn_qualifier']
                f = aws.get_function(FunctionName=lambda_name, Qualifier=q)
                logging.info(
                    "retrieved func config: {0}".format(f['Configuration']))
                latest_funcs[lambda_name] = {
                    "arn": alias_arn,
                    "arn_qualifier": q
                }
                func_definition.append({
                    "Id": "{0}".format(lambda_name.lower()),
                    "FunctionArn": alias_arn,
                    "FunctionConfiguration": {
                        "Executable": f['Configuration']['Handler'],
                        "MemorySize":
                            int(f['Configuration']['MemorySize']) * 1000,
                        "Timeout": int(f['Configuration']['Timeout'])
                    }
                })  # function definition
            except Exception as e:
                logging.error(e)

        # if we found one or more configured functions, create a func definition
        if len(func_definition) > 0:
            ll = gg_client.create_function_definition(
                Name="{0}_func_def".format(group_type.type_name)
            )
            lmbv = gg_client.create_function_definition_version(
                FunctionDefinitionId=ll['Id'],
                Functions=func_definition
            )
            # update config with latest function versions
            config['lambda_functions'] = latest_funcs
            ll_arn = lmbv['Arn']
            logging.info("Created Function definition ARN:{0}".format(ll_arn))
            config['func_def'] = {'id': ll['Id'], 'version_arn': ll_arn}
            return ll_arn
        else:
            return

    @staticmethod
    def _create_logger_definition(gg_client, group_type, config):
        log_info = gg_client.create_logger_definition(
            Name="{0}_logger_def".format(group_type.type_name)
        )
        logv = gg_client.create_logger_definition_version(
            LoggerDefinitionId=log_info['Id'],
            Loggers=[{
                "Id": "gg-logging",
                "Component": "GreengrassSystem", "Level": "INFO",
                "Space": 5000,  # size in KB
                "Type": "FileSystem"
            }, {
                "Id": "func-logging",
                "Component": "Lambda", "Level": "INFO",
                "Space": 5000,  # size in KB
                "Type": "FileSystem"
            }]
        )
        log_arn = logv['Arn']
        logging.info("Created Lambda definition ARN:{0}".format(log_arn))
        config['logger_def'] = {
            "id": log_info['Id'],
            "version_arn": log_arn
        }

        return log_arn

    @staticmethod
    def _create_subscription_definition(gg_client, group_type, config):
        """
        Configure routing subscriptions for a Greengrass group.

        group_type: either default or an overridden group type
        config: GroupConfigFile object used for routing subscriptions
        """
        logging.info('[begin] Configuring routing subscriptions')
        sub_info = gg_client.create_subscription_definition(
            Name="{0}_routing".format(group_type.type_name)
        )
        logging.info('Created subscription definition: {0}'.format(sub_info))

        subs = group_type.get_subscription_definition(config=config)
        if subs is None:
            logging.warning(
                "[end] No SubscriptionDefinition exists in GroupType:{0}".format(
                    group_type.type_name)
            )
            return

        subv = gg_client.create_subscription_definition_version(
            SubscriptionDefinitionId=sub_info['Id'],
            Subscriptions=subs
        )
        sub_arn = subv['Arn']
        config['subscription_def'] = {
            "id": sub_info['Id'],
            "version_arn": sub_arn
        }
        logging.info('[end] Configured routing subscriptions')
        return sub_arn

    @staticmethod
    def _delete_group(config_file, region, profile_name):
        logging.info('[begin] Deleting Group')
        config = GroupConfigFile(config_file=config_file)

        # delete the Greengrass Group entities
        gg_client = _get_gg_session(region=region, profile_name=profile_name)

        logger_def_id = config['logger_def']['id']
        logging.info('Deleting logger_def_id:{0}'.format(logger_def_id))
        try:
            gg_client.delete_logger_definition(LoggerDefinitionId=logger_def_id)
        except ClientError as ce:
            logging.error(ce)

        func_def_id = config['func_def']['id']
        logging.info('Deleting func_def_id:{0}'.format(func_def_id))
        try:
            gg_client.delete_function_definition(
                FunctionDefinitionId=func_def_id
            )
        except ClientError as ce:
            logging.error(ce)

        device_def_id = config['device_def']['id']
        logging.info('Deleting device_def_id:{0}'.format(device_def_id))
        try:
            gg_client.delete_device_definition(DeviceDefinitionId=device_def_id)
        except ClientError as ce:
            logging.error(ce)

        core_def_id = config['core_def']['id']
        logging.info('Deleting core_def_id:{0}'.format(core_def_id))
        try:
            gg_client.delete_core_definition(CoreDefinitionId=core_def_id)
        except ClientError as ce:
            logging.error(ce)

        group_id = config['group']['id']
        logging.info('Deleting group_id:{0}'.format(group_id))
        deployments = gg_client.list_deployments(
            GroupId=group_id, MaxResults='1'
        )
        if len(deployments['Deployments']) > 0:
            # there were previous deployments which need reset before delete
            logging.info('Reset deployments:{0} for group_id:{1}'.format(
                deployments, group_id))
            gg_client.reset_deployments(GroupId=group_id)

        try:
            gg_client.delete_group(GroupId=group_id)
        except ClientError as ce:
            logging.error(ce)
            return
        logging.info('[end] Deleted group')

    @staticmethod
    def _delete_thing(cert_arn, cert_id, thing_name, region, policy_name,
                      profile_name):
        iot_client = _get_iot_session(region=region, profile_name=profile_name)

        try:
            # update certificate to an INACTIVE status.
            logging.info('[_delete_thing] deactivating cert:{0}'.format(
                cert_id))
            iot_client.update_certificate(
                certificateId=cert_id, newStatus='INACTIVE'
            )
            # Next, detach the Thing principal/certificate from the Thing.
            logging.info('[_delete_thing] detach cert')
            iot_client.detach_thing_principal(
                thingName=thing_name, principal=cert_arn
            )
            logging.info('[_delete_thing] detach principal policy:{0}'.format(
                policy_name)
            )
            iot_client.detach_principal_policy(
                policyName=policy_name, principal=cert_arn
            )
            # finally delete the Certificate
            iot_client.delete_certificate(certificateId=cert_id)
        except ClientError as ce:
            logging.error(ce)

        # delete the Thing
        logging.info('Deleting thing_name:{0}'.format(thing_name))
        try:
            thing = iot_client.describe_thing(thingName=thing_name)
            iot_client.delete_thing(
                thingName=thing_name, expectedVersion=thing['version']
            )
        except ClientError as ce:
            logging.error(ce)

    @staticmethod
    def _create_attach_thing_policy(cert_arn, thing_policy, iot_client,
                                    policy_name):
        if thing_policy:
            try:
                iot_client.create_policy(
                    policyName=policy_name,
                    policyDocument=thing_policy
                )
            except ClientError as ce:
                if ce.response['Error']['Code'] == 'EntityAlreadyExists':
                    logging.warning(
                        "Policy '{0}' exists. Using existing Policy".format(
                            policy_name))
                else:
                    logging.error("Unexpected Error: {0}".format(ce))
            except BaseException as e:
                logging.error("Error type: {0} message: {1}".format(
                    e, str(type(e))))

            # even if there's an exception creating the policy, try to attach
            iot_client.attach_principal_policy(
                policyName=policy_name,
                principal=cert_arn
            )
            logging.info("Created {0} and attached to {1}".format(
                policy_name, cert_arn))
        else:
            logging.warning("No thing policy to create and attach.")

    def _most_restrictive_arn(self, account_id, region):
        if account_id is None:
            account_id = self._account_id

        # Make as restrictive as generically possible.
        if account_id is None:
            arn = "arn:aws:iot:{0}:*:*".format(region)
        else:
            arn = "arn:aws:iot:{0}:{1}:*".format(region, account_id)

        return arn

    def clean_core(self, config_file, region=None, profile_name=None):
        """
        Clean all Core related provisioned artifacts from both the local file
        and the AWS Greengrass service.

        :param config_file: config file containing the core to clean
        :param region: the region in which the core should be cleaned.
            [default: us-west-2]
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        :return:
        """
        config = GroupConfigFile(config_file=config_file)

        if region is None:
            region = self._region

        # delete the Core's Certificate
        core_cert_id = config['core']['cert_id']
        core_cert_arn = config['core']['cert_arn']
        core_thing_name = config['core']['thing_name']
        policy_name = config['misc']['policy_name']
        logging.info('Deleting core_thing_name:{0}'.format(core_thing_name))
        GroupCommands._delete_thing(
            cert_arn=core_cert_arn, cert_id=core_cert_id,
            thing_name=core_thing_name, region=region,
            policy_name=policy_name, profile_name=profile_name
        )
        config.make_core_fresh()

    def clean_devices(self, config_file, region=None, profile_name=None):
        """
        Clean all device related provisioned artifacts from both the local file
        and the AWS Greengrass service.

        :param config_file: config file containing the devices to clean
        :param region: the region in which the devices should be cleaned.
            [default: us-west-2]
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        config = GroupConfigFile(config_file=config_file)
        if region is None:
            region = self._region

        devices = config['devices']
        if 'device_thing_name' in devices:
            logging.info('Configured devices already clean')
            return

        policy_name = config['misc']['policy_name']
        for device in devices:
            cert_arn = devices[device]['cert_arn']
            cert_id = devices[device]['cert_id']
            thing_name = device
            logging.info('Deleting device_thing_name:{0}'.format(thing_name))
            GroupCommands._delete_thing(
                cert_arn, cert_id, thing_name, region, policy_name, profile_name
            )
        config.make_devices_fresh()

    @staticmethod
    def clean_file(config_file):
        """
        Clean all provisioned artifacts from the local config file.

        :param config_file: config file of the group to clean
        """
        logging.info('[begin] Cleaning config file')
        config = GroupConfigFile(config_file=config_file)

        if config.is_fresh() is True:
            raise ValueError("Config is already clean.")
        config.make_fresh()
        logging.info('[end] Cleaned config file:{0}'.format(config_file))

    def clean_all(self, config_file, region=None, profile_name=None):
        """
        Clean all provisioned artifacts from both the local file and the AWS
        Greengrass service.

        :param config_file: config file containing the group to clean
        :param region: the region in which the group should be cleaned.
            [default: us-west-2]
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        logging.info('[begin] Cleaning all provisioned artifacts')
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh() is True:
            raise ValueError("Config is already clean.")

        if region is None:
            region = self._region

        self._delete_group(
            config_file, region=region, profile_name=profile_name)
        self.clean_core(config_file, region=region)
        self.clean_devices(config_file, region=region)
        self.clean_file(config_file)

        logging.info('[end] Cleaned all provisioned artifacts')

    def deploy(self, config_file, region=None, profile_name=None):
        """
        Deploy the configuration and Lambda functions of a Greengrass group to
        the Greengrass core contained in the group.

        :param config_file: config file of the group to deploy
        :param region: the region from which to deploy the group.
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh():
            raise ValueError("Config not yet tracking a group. Cannot deploy.")

        if region is None:
            region = self._region

        gg_client = _get_gg_session(region=region, profile_name=profile_name)

        dep_req = gg_client.create_deployment(
            GroupId=config['group']['id'],
            GroupVersionId=config['group']['version'],
            DeploymentType="NewDeployment"
        )
        print("Group deploy requested for deployment_id:{0}".format(
            dep_req['DeploymentId'],
        ))

    def create_thing(self, thing_name, region=None, cert_dir=None, force=False):
        if region is None:
            region = self._region
        iot_client = _get_iot_session(region=region)
        ###
        # Here begins the essence of the `create_thing` command
        # Create a Key and Certificate in the AWS IoT service per Thing
        keys_cert = iot_client.create_keys_and_certificate(setAsActive=True)
        # Create a named Thing in the AWS IoT Service
        thing = iot_client.create_thing(thingName=thing_name)
        iot_client.update_thing(
            thingName=thing_name,
            attributePayload={
                'attributes': {
                    'thingArn': thing['thingArn'],
                    'certificateId': keys_cert['certificateId']
                },
                'merge': True
            }
        )
        # Attach the previously created Certificate to the created Thing
        iot_client.attach_thing_principal(
            thingName=thing_name, principal=keys_cert['certificateArn'])
        # This ends the essence of the `create_core` command
        ###
        if cert_dir is None:
            cfg_dir = os.getcwd()
        else:
            cfg_dir = cert_dir

        # Save all Key and Certificate files locally for future use
        try:
            cert_name = cfg_dir + '/' + thing_name + ".pem"
            public_key_file = cfg_dir + '/' + thing_name + ".pub"
            private_key_file = cfg_dir + '/' + thing_name + ".prv"
            with open(cert_name, "w") as pem_file:
                pem = keys_cert['certificatePem']
                pem_file.write(pem)
                logging.info("Thing Name: {0} and PEM file: {1}".format(
                    thing_name, cert_name))

            with open(public_key_file, "w") as pub_file:
                pub = keys_cert['keyPair']['PublicKey']
                pub_file.write(pub)
                logging.info("Thing Name: {0} Public Key File: {1}".format(
                    thing_name, public_key_file))

            with open(private_key_file, "w") as prv_file:
                prv = keys_cert['keyPair']['PrivateKey']
                prv_file.write(prv)
                logging.info("Thing Name: {0} Private Key File: {1}".format(
                    thing_name, private_key_file))
        except OSError as ose:
            logging.error(
                'OSError while writing a key or cert file. {0}'.format(ose)
            )
        return keys_cert, thing

    def create_core(self, thing_name, config_file, region=None,
                    cert_dir=None, account_id=None,
                    policy_name='ggc-default-policy', profile_name=None):
        """
        Using the `thing_name` value, creates a Thing in AWS IoT, attaches and
        downloads new keys & certs to the certificate directory, then records
        the created information in the local config file for inclusion in the
        Greengrass Group as a Greengrass Core.

        :param thing_name: the name of the thing to create and use as a
            Greengrass Core
        :param config_file: config file used to track the Greengrass Core in the
            group
        :param region: the region in which to create the new core.
            [default: us-west-2]
        :param cert_dir: the directory in which to store the thing's keys and
            certs. If `None` then use the current directory.
        :param account_id: the account_id in which to create the new core.
            [default: None]
        :param policy_name: the name of the policy to associate with the device.
            [default: 'ggc-default-policy']
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh() is False:
            raise ValueError(
                "Config file already tracking previously created core or group"
            )
        if region is None:
            region = self._region
        if account_id is None:
            account_id = self._account_id
        keys_cert, thing = self.create_thing(thing_name, region, cert_dir)

        cert_arn = keys_cert['certificateArn']
        config['core'] = {
            'thing_arn': thing['thingArn'],
            'cert_arn': cert_arn,
            'cert_id': keys_cert['certificateId'],
            'thing_name': thing_name
        }
        logging.debug("create_core cfg:{0}".format(config))
        logging.info("Thing:'{0}' associated with cert:'{1}'".format(
            thing_name, cert_arn))
        core_policy = self.get_core_policy(
            core_name=thing_name, account_id=account_id, region=region)
        iot_client = _get_iot_session(region=region, profile_name=profile_name)
        self._create_attach_thing_policy(
            cert_arn, core_policy,
            iot_client=iot_client, policy_name=policy_name
        )
        misc = config['misc']
        misc['policy_name'] = policy_name
        config['misc'] = misc

    def get_core_policy(self, core_name, account_id=None, region=None):
        if region is None:
            region = self._region
        arn = self._most_restrictive_arn(account_id, region)

        core_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iot:Publish",
                        "iot:Subscribe",
                        "iot:Connect",
                        "iot:Receive",
                        "iot:GetThingShadow",
                        "iot:DeleteThingShadow",
                        "iot:UpdateThingShadow"
                    ],
                    "Resource": [arn]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "greengrass:AssumeRoleForGroup",
                        "greengrass:CreateCertificate",
                        "greengrass:GetConnectivityInfo",
                        "greengrass:GetDeployment",
                        "greengrass:GetDeploymentArtifacts",
                        "greengrass:UpdateConnectivityInfo",
                        "greengrass:UpdateCoreDeploymentStatus"
                    ],
                    "Resource": ["*"]
                }
            ]
        }
        return json.dumps(core_policy)

    def create_devices(self, thing_names, config_file, region=None,
                       cert_dir=None, append=False, account_id=None,
                       policy_name='ggd-discovery-policy', profile_name=None):
        """
        Using the `thing_names` values, creates Things in AWS IoT, attaches and
        downloads new keys & certs to the certificate directory, then records
        the created information in the local config file for inclusion in the
        Greengrass Group as Greengrass Devices.

        :param thing_names: the thing name or list of thing names to create and
            use as Greengrass Devices
        :param config_file: config file used to track the Greengrass Devices in
            the group
        :param region: the region in which to create the new devices.
            [default: us-west-2]
        :param cert_dir: the directory in which to store the thing's keys and
            certs. If `None` then use the current directory.
        :param append: append the created devices to the list of devices in the
            config file. [default: False]
        :param account_id: the account ID in which to create devices. If 'None'
            the config_file will be checked for an `account_id` value in the
            `misc` section.
        :param policy_name: the name of the policy to associate with the device.
            [default: 'ggd-discovery-policy']
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        logging.info("create_devices thing_names:{0}".format(thing_names))
        config = GroupConfigFile(config_file=config_file)
        if append is False and config.is_device_fresh() is False:
            raise ValueError(
                "Config file tracking previously created devices. Append "
                "devices instead"
            )

        if region is None:
            region = self._region
        if account_id is None:
            account_id = self._account_id
        devices = dict()
        if append:
            devices = config['devices']
        if type(thing_names) is str:
            thing_names = [thing_names]

        iot_client = _get_iot_session(region=region, profile_name=profile_name)
        for thing_name in thing_names:
            keys_cert, thing = self.create_thing(thing_name, region, cert_dir)
            cert_arn = keys_cert['certificateArn']
            devices[thing_name] = {
                'thing_arn': thing['thingArn'],
                'cert_arn': cert_arn,
                'cert_id': keys_cert['certificateId'],
                'thing_name': thing_name
            }
            logging.info("Thing:'{0}' associated with cert:'{1}'".format(
                thing_name, cert_arn))
            device_policy = self.get_device_policy(
                device_name=thing_name, account_id=account_id, region=region
            )
            self._create_attach_thing_policy(cert_arn, device_policy,
                                             iot_client, policy_name)

        config['devices'] = devices
        logging.info("create_devices cfg:{0}".format(config))

    def associate_devices(self, thing_names, config_file, region=None,
                          profile_name=None):
        # TODO remove this function when Group discovery is enriched
        """
        Using the `thing_names` values, associate existing Things in AWS IoT
        with the config of another Greengrass Group for use as Greengrass
        Devices.

        :param thing_names: the thing name or list of thing names to associate
            as Greengrass Devices
        :param config_file: config file used to track the Greengrass Devices in
            the group
        :param region: the region in which to associate devices.
            [default: us-west-2]
        :param profile_name: the name of the `awscli` profile to use.
            [default: None]
        """
        logging.info("associate_devices thing_names:{0}".format(thing_names))
        config = GroupConfigFile(config_file=config_file)
        if region is None:
            region = self._region
        devices = config['devices']
        if type(thing_names) is str:
            thing_names = [thing_names]
        iot_client = _get_iot_session(region=region, profile_name=profile_name)
        for thing_name in thing_names:
            thing = iot_client.describe_thing(thingName=thing_name)
            logging.info("Found existing Thing:{0}".format(thing))
            p = iot_client.list_thing_principals(thingName=thing_name)
            logging.info("Existing Thing has principals:{0}".format(p))
            devices[thing_name] = {
                'thing_arn': thing['attributes']['thingArn'],
                'cert_arn': p['principals'][0],
                'cert_id': thing['attributes']['certificateId'],
                'thing_name': thing_name
            }
            logging.info("Thing:'{0}' associated with config:'{1}'".format(
                thing_name, config_file))

        config['devices'] = devices

    def get_device_policy(self, device_name, account_id, region=None):
        if region is None:
            region = self._region
        arn = self._most_restrictive_arn(account_id, region)
        device_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "greengrass:Discover",
                "Resource": ["*"]
            }]
        }
        return json.dumps(device_policy)


def main():
    from .mock_group import MockGroupType
    gc = GroupCommands(
        group_types={MockGroupType.MOCK_TYPE: MockGroupType},
        region='us-west-2'
    )
    fire.Fire(gc)


if __name__ == '__main__':
    main()
