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
import json
import boto3
import logging
from boto3.session import Session
from botocore.exceptions import ClientError

__version__ = '0.1.0'

logging.basicConfig(format='%(asctime)s|%(name)-8s|%(levelname)s: %(message)s',
                    level=logging.INFO)


class GroupConfigFile(object):
    def __init__(self, config_file='cfg.json'):
        super(GroupConfigFile, self).__init__()
        self.config_file = config_file
        if self.get_config() is None:
            raise ValueError("Error reading config file: {0}".format(
                self.config_file))

    def get_config(self):
        config = None
        if os.path.exists(self.config_file) and os.path.isfile(
                self.config_file):
            try:
                with open(self.config_file, "r") as in_file:
                    config = json.load(in_file)
            except OSError as ose:
                logging.error(
                    'OSError while reading config file. {0}'.format(ose))
        return config

    def update(self, **kwargs):
        if len(kwargs.keys()) == 0:
            logging.warning("No new configuration to update.")
            return
        # config['group'] = {"id": group_info['Id']}
        config = self.get_config()
        if 'core' in kwargs:
            for key, val in kwargs['core']:
                config['core'][key] = val
            kwargs.pop('core')
        if 'lambda_functions' in kwargs:
            for key in kwargs['lambda_functions']:
                config['lambda_functions'][key] = kwargs['lambda_functions'][
                    key]
            kwargs.pop('lambda_functions')
        if 'devices' in kwargs:
            for key in kwargs['devices']:
                config['devices'][key] = kwargs['devices'][key]
            kwargs.pop('devices')
        if 'core_def' in kwargs:
            for key, val in kwargs['core_def']:
                config['core_def'][key] = val
            kwargs.pop('core_def')
        if 'device_def' in kwargs:
            for key, val in kwargs['device_def']:
                config['device_def'][key] = val
            kwargs.pop('device_def')
        if 'group' in kwargs.keys():
            for key, val in kwargs['group']:
                logging.info('Updating group key:{0} and value:{0}'.format(
                    key, val))
                config['group'][key] = val
            kwargs.pop('group')

        if len(kwargs) > 0:
            # treat the rest of the kwargs as simple property value assignments
            for key in kwargs.keys():
                logging.info("Update config key:{0}".format(key))
                config[key] = kwargs[key]
        self.write_config(config)

    def write_config(self, config):
        try:
            with open(self.config_file, "w") as out_file:
                json.dump(config, out_file, indent=2,
                          separators=(',', ': '), sort_keys=True)
                logging.debug(
                    'Config file:{0} updated.'.format(self.config_file))
        except OSError as ose:
            logging.error(
                'OSError while writing config file. {0}'.format(ose))

    def is_fresh(self):
        cfg = self.get_config()
        if cfg is not None:
            if all(x == '' for x in (
                    cfg['group']['id'], cfg['func_def']['id'],
                    cfg['core_def']['id'], cfg['device_def']['id'],
                    cfg['logger_def']['id']
            )):
                return True

        return False

    def make_fresh(self):
        config = self.get_config()
        config['group']['id'] = ''
        config['group']['version'] = ''
        config['group']['version_arn'] = ''
        config['core_def']['id'] = ''
        config['core_def']['version_arn'] = ''
        config['device_def']['id'] = ''
        config['device_def']['version_arn'] = ''
        config['func_def']['id'] = ''
        config['func_def']['version_arn'] = ''
        config['logger_def']['id'] = ''
        config['logger_def']['version_arn'] = ''
        config['subscription_def']['id'] = ''
        config['subscription_def']['version_arn'] = ''
        self.write_config(config=config)

    def read(self, prop):
        return self.get_config()[prop]

    def __getitem__(self, prop):
        return self.read(prop)

    def __setitem__(self, key, val):
        cfg = self.get_config()
        cfg[key] = val
        self.write_config(cfg)


class GroupType(object):
    MOCK_TYPE = 'mock'

    def __init__(self, type_name='mock', config=None, region='us-west-2'):
        super(GroupType, self).__init__()
        self.type_name = type_name
        self.config = config
        self.region = region

    # TODO revise the thing policy with min privileges required
    # TODO revise the thing policy with min resources required
    def create_and_attach_thing_policy(self):
        if self.config['core']['thing_name'] is '<device_thing_name>':
            raise ValueError("Config file values seem to be mis-configured.")

        # Create and attach to the principal/certificate the minimal action
        # privileges Thing policy that allows publish and subscribe
        thing_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "iot:*",
                    "greengrass:*"
                    # "iot:Connect",
                    # "iot:Publish",
                    # "iot:Receive",
                    # "iot:Subscribe"
                ],
                "Resource": [
                    # "arn:aws:iot:{0}:*:*".format(region)
                    "*"
                ]
            }]
        }

        iot = Session(region_name=self.region).client('iot')
        policy_name = '{0}-{1}'.format(self.type_name,
                                       self.config['core']['thing_name'])
        policy = json.dumps(thing_policy)
        logging.debug('[create_and_attach_thing_policy] policy:{0}'.format(policy))
        try:
            p = iot.create_policy(
                policyName=policy_name,
                policyDocument=policy
            )
            logging.debug(
                "[create_and_attach_thing_policy] Created Policy: {0}".format(
                    p['policyName']))

            cert_arn = self.config['core']['cert_arn']
            iot.attach_principal_policy(policyName=policy_name,
                                        principal=cert_arn)
            logging.debug(
                "[create_and_attach_thing_policy] Attached {0} to {1}".format(
                    policy_name, cert_arn))
            return p['policyName'], p['policyArn']

        except ClientError as ce:
            if ce.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                logging.warning(
                    "[create_and_attach_thing_policy] {0}".format(
                        ce.response['Error']['Message']))
            # since policy already exists return nothing, assuming previous success

    def create_and_attach_iam_role(self):
        logging.info("[begin] [create_and_attach_iam_role]")
        iam = Session(region_name=self.region).client('iam')
        iam_res = Session(region_name=self.region).resource('iam')
        gg_client = boto3.client('greengrass', region_name=self.region)
        role_name = '{0}_service_role'.format(self.type_name)
        aws_lambda_ro_access_arn = "arn:aws:iam::aws:policy/AWSLambdaReadOnlyAccess"
        aws_iot_full_access_arn = "arn:aws:iam::aws:policy/AWSIoTFullAccess"

        assume_role_policy = {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "Service": "greengrass.amazonaws.com"
                  },
                  "Action": "sts:AssumeRole"
                }
              ]
            }
        gg_inline_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "g3s20170630",
                    "Effect": "Allow",
                    "Action": [
                        "greengrass:*"
                    ],
                    "Resource": [
                        "*"
                    ]
                }
            ]
        }
        try:
            resp = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )
            logging.debug(
                "[create_and_attach_iam_role] create_role {0}".format(resp))
            resp = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=aws_lambda_ro_access_arn
            )
            logging.debug(
                "[create_and_attach_iam_role] attach_policy 1 {0}".format(resp))
            resp = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=aws_iot_full_access_arn
            )
            logging.debug(
                "[create_and_attach_iam_role] attach_policy 2 {0}".format(resp))
            resp = iam.put_role_policy(
                RoleName=role_name,
                PolicyName='g3s_inline_policy',
                PolicyDocument=json.dumps(gg_inline_policy)
            )
            logging.debug(
                "[create_and_attach_iam_role] put_policy {0}".format(resp))
            role = iam_res.Role(role_name)
            gg_client.attach_service_role_to_account(RoleArn=role.arn)
            logging.info(
                "[end] [create_and_attach_iam_role] attached service role")

        except ClientError as ce:
            if ce.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                logging.warning(
                    "[create_and_attach_iam_role] {0}".format(
                        ce.response['Error']['Message']))
            else:
                logging.error("[create_and_attach_iam_role] {0}".format(
                        ce.response['Error']['Message']))
            # since role already exists return nothing, assuming previous success

    def get_core_definition(self, config):
        if GroupType.MOCK_TYPE is self.type_name:
            return [{
                "ThingArn": config['core']['thing_arn'],
                "CertificateArn": config['core']['cert_arn'],
                "Id": "{0}_00".format(self.type_name),
                "SyncShadow": True
            }]
        else:
            raise NotImplementedError(
                'Override get_core_definition for group type {0}.'.format(
                    self.type_name
                ))

    def get_device_definition(self, config):
        if GroupType.MOCK_TYPE is self.type_name:
            return [{
                    "Id": "{0}_10".format(self.type_name),
                    "ThingArn": config['devices']['GGD_example']['thing_arn'],
                    "CertificateArn":
                        config['devices']['GGD_example']['cert_arn'],
                    "SyncShadow": False
            }]
        else:
            raise NotImplementedError(
                'Override get_device_definition for group type {0}.'.format(
                    self.type_name
                ))

    def get_subscription_definition(self, config):
        d = config['devices']
        l = config['lambda_functions']
        s = config['subscriptions']

        if GroupType.MOCK_TYPE is self.type_name:
            return [
                {
                    "Id": "1",
                    "Source": d['GGD_example']['thing_arn'],
                    "Subject": s['telemetry'],
                    "Target": l['MockDevice']['arn']
                },
                {
                    "Id": "4",
                    "Source": d['GGD_example']['thing_arn'],
                    "Subject": s['telemetry'],
                    "Target": "cloud"
                },
                {
                    "Id": "14",
                    "Source": l['MockDevice']['arn'],
                    "Subject": s['errors'],
                    "Target": "cloud"
                }
            ]
        else:
            raise NotImplementedError(
                'Override get_subscription_definition for group type {0}.'.format(
                    self.type_name
                ))
