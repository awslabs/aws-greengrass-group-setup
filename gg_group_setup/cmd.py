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

import fire
import boto3
import logging
from botocore.exceptions import ClientError
from gg_group_setup import GroupConfigFile, MockGroupType

logging.basicConfig(format='%(asctime)s|%(name)-8s|%(levelname)s: %(message)s',
                    level=logging.INFO)


class GroupCommands(object):
    # set your own group types to this dict for use by the commands
    group_types = {}

    def create(self, config_file, group_type=MockGroupType.MOCK_TYPE,
               group_name=None, region='us-west-2'):
        """
        Create a Greengrass group in the given region.

        config_file: config file of the group to create
        group_type: either the default or an overridden group type
        group_name: the name of the group. If no name is given then group_type
                    will be used.
        region: the region in which to create the new group.
        """
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh() is False:
            raise ValueError(
                "Config file already tracking previously created group"
            )

        self.group_types[MockGroupType.MOCK_TYPE] = MockGroupType

        if group_type not in self.group_types.keys():
            raise ValueError("Can only create {0} groups.".format(
                self.group_types)
            )

        # create an instance of the requested group type around the config file
        gt = self.group_types[group_type](config=config, region=region)

        # Create a Group
        logging.info("[begin] Creating a Greengrass Group")
        if group_name is None:
            group_name = group_type

        gg_client = boto3.client("greengrass", region_name=region)

        group_info = gg_client.create_group(Name="{0}_group".format(group_name))
        config['group'] = {"id": group_info['Id']}
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
            gg_client=gg_client, group_type=gt, config=config
        )
        log_arn = self._create_logger_definition(
            gg_client=gg_client, group_type=gt, config=config
        )
        sub_arn = self._create_subscription_definition(
            gg_client=gg_client, group_type=gt, config=config
        )

        # Add all the constituent parts to the Greengrass Group
        grp = gg_client.create_group_version(
            GroupId=group_info['Id'],
            CoreDefinitionVersionArn=cl_arn,
            DeviceDefinitionVersionArn=dl_arn,
            FunctionDefinitionVersionArn=lv_arn,
            LoggerDefinitionVersionArn=log_arn,
            SubscriptionDefinitionVersionArn=sub_arn
        )
        config['group'] = {
            "id": group_info['Id'],
            "version_arn": grp['Arn'],
            "version": grp['Version']
        }
        logging.info("[end] Created Greengrass Group {0}".format(group_info['Id']))

    def _create_core_definition(self, gg_client, group_type, config, group_name):
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
            logging.info("CoreDefinition already exists:{0}".format(core_def_id))
            return

    def _create_device_definition(self, gg_client, group_type, config, group_name):
        device_def = group_type.get_device_definition(config=config)
        device_def_id = config['device_def']['id']
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

    def _create_function_definition(self, gg_client, group_type, config):
        # Add latest version of Lambda functions to a Function definition
        aws = boto3.client('lambda')
        latest_funcs = dict()
        func_definition = []
        # first determine the latest versions of configured Lambda functions
        for key in config['lambda_functions']:
            lambda_name = key
            a = aws.list_aliases(FunctionName=lambda_name)
            # assume only one Alias associated with the Lambda function
            alias_arn = a['Aliases'][0]['AliasArn']
            logging.info("function {0}, found aliases: {1}".format(
                lambda_name, a)
            )

            # get the function pointed to by the alias
            q = config['lambda_functions'][lambda_name]['arn_qualifier']
            f = aws.get_function(FunctionName=lambda_name, Qualifier=q)
            logging.info("retrieved func config: {0}".format(f['Configuration']))
            latest_funcs[lambda_name] = {
                "arn": alias_arn,
                "arn_qualifier": q
            }
            func_definition.append({
                "Id": "{0}".format(lambda_name.lower()),
                "FunctionArn": alias_arn,
                "FunctionConfiguration": {
                    "Executable": f['Configuration']['Handler'],
                    "MemorySize": int(f['Configuration']['MemorySize']) * 1000,
                    "Timeout": int(f['Configuration']['Timeout'])
                }
            })  # function definition

        # if we found one or more configured functions, create a func definition
        if len(func_definition) > 0:
            ll = gg_client.create_function_definition(
                Name="{0}_func_def".format(group_type.type_name)
            )
            lmbv = gg_client.create_function_definition_version(
                FunctionDefinitionId=ll['Id'],
                Functions=func_definition
            )
            config['lambda_functions'] = latest_funcs  # update config with versions
            ll_arn = lmbv['Arn']
            logging.info("Created Function definition ARN:{0}".format(ll_arn))
            config['func_def'] = {'id': ll['Id'], 'version_arn': ll_arn}
            return ll_arn
        else:
            return '<no_functions>'

    def _create_logger_definition(self, gg_client, group_type, config):
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
                "Component": "Lambda", "Level": "DEBUG",
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

    def _create_subscription_definition(self, gg_client, group_type, config):
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

    def _delete(self, config_file, region='us-west-2'):
        logging.info('[begin] Deleting Group')
        config = GroupConfigFile(config_file=config_file)

        gg_client = boto3.client("greengrass", region_name=region)

        logger_def_id = config['logger_def']['id']
        logging.info('Deleting logger_def_id:{0}'.format(logger_def_id))
        try:
            gg_client.delete_logger_definition(LoggerDefinitionId=logger_def_id)
        except ClientError as ce:
            logging.error(ce.message)

        func_def_id = config['func_def']['id']
        logging.info('Deleting func_def_id:{0}'.format(func_def_id))
        try:
            gg_client.delete_function_definition(FunctionDefinitionId=func_def_id)
        except ClientError as ce:
            logging.error(ce.message)

        device_def_id = config['device_def']['id']
        logging.info('Deleting device_def_id:{0}'.format(device_def_id))
        try:
            gg_client.delete_device_definition(DeviceDefinitionId=device_def_id)
        except ClientError as ce:
            logging.error(ce.message)

        core_def_id = config['core_def']['id']
        logging.info('Deleting core_def_id:{0}'.format(core_def_id))
        try:
            gg_client.delete_core_definition(CoreDefinitionId=core_def_id)
        except ClientError as ce:
            logging.error(ce.message)

        group_id = config['group']['id']
        logging.info('Deleting group_id:{0}'.format(group_id))
        try:
            gg_client.delete_group(GroupId=group_id)
        except ClientError as ce:
            logging.error(ce.message)
            return

        logging.info('[end] Deleted group')

    def clean_file(self, config_file):
        logging.info('[begin] Cleaning config file')
        config = GroupConfigFile(config_file=config_file)

        if config.is_fresh() is True:
            raise ValueError("Config is already clean.")
        config.make_fresh()
        logging.info('[end] Cleaned config file:{0}'.format(config_file))

    def clean_all(self, config_file, region='us-west-2'):
        logging.info('[begin] Cleaning all provisioned artifacts')
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh() is True:
            raise ValueError("Config is already clean.")

        self._delete(config_file, region=region)
        self.clean_file(config_file)

        logging.info('[end] Cleaned all provisioned artifacts')

    def deploy(self, config_file, region='us-west-2'):
        config = GroupConfigFile(config_file=config_file)
        if config.is_fresh():
            raise ValueError("Config not yet tracking a group. Cannot deploy.")

        gg_client = boto3.client("greengrass", region_name=region)
        dep_req = gg_client.create_deployment(
            GroupId=config['group']['id'],
            GroupVersionId=config['group']['version'],
            DeploymentType="NewDeployment"
        )
        print("Group deploy requested for deployment_id:{0}".format(
            dep_req['DeploymentId'],
        ))


def main():
    fire.Fire(GroupCommands())


if __name__ == '__main__':
    main()
