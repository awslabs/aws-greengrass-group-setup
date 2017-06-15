"""
greengrass-group-setup
----------------------
"""
import os
from setuptools import setup
from group_setup import __version__


def open_file(fname):
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name='greengrass-group-setup',
    version=__version__,
    url='https://github.com/awslabs/aws-greengrass-group-setup',
    license=open("LICENSE.md").read(),
    author='Brett Francis',
    author_email='brettf@amazon.com',
    description='A file driven approach to the creation of an entire AWS Greengrass group',
    long_description=open_file("README.md").read(),
    py_modules=['group_setup'],
    zip_safe=False,
    include_package_data=True,
    install_requires=['boto3>=1.4.4', 'fire>=0.1.1'],
    packages=["group_setup"],
    keywords='greengrass group aws iot',
    entry_points='''
        [console_scripts]
        group_setup=group_setup.cmd:main
    ''',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Environment :: Web Environment',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
    ]
)