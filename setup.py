"""
greengrass-group-setup
----------------------
"""

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
from setuptools import setup
from gg_group_setup import __version__


def open_file(fname):
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name='gg_group_setup',
    version=__version__,
    url='https://github.com/awslabs/aws-greengrass-group-setup',
    license="Apache License 2.0",
    author='Brett Francis',
    author_email='brettf@amazon.com',
    description='A file-driven approach to the creation of an entire AWS Greengrass group',
    long_description=open_file("README.rst").read(),
    py_modules=['group_setup'],
    zip_safe=False,
    include_package_data=True,
    install_requires=['boto3>=1.4.4', 'fire>=0.1.1'],
    packages=["gg_group_setup"],
    keywords='greengrass group aws iot',
    entry_points='''
        [console_scripts]
        gg_group_setup=gg_group_setup:main
    ''',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Environment :: Web Environment',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
    ]
)