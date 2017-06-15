
"""
A mock device Lambda
"""
from __future__ import print_function
import json
import time
import random
import logging
import greengrasssdk

gg_client = greengrasssdk.client('iot-data')


def mock_temp():
    return random.randint(-30, 115)


def mock_voltage():
    random.randint(1, 1000)


def mock_amperage():
    random.uniform(0.0, 40.0)


def get_shadow_state():
    logging.info("[get_shadow_state]")
    return json.loads(gg_client.get_thing_shadow(thingName='MockDevice'))


def get_pub_frequency(mock_shadow):
    if 'state' in mock_shadow is False or \
        'reported' in mock_shadow['state'] is False or \
            'pub_frequency' in mock_shadow['state']['reported'] is False:
            return 1

    return mock_shadow['state']['reported']['pub_frequency']


def get_pub_topic(mock_shadow):
    if 'state' in mock_shadow is False or \
        'reported' in mock_shadow['state'] is False or \
            'pub_topic' in mock_shadow['state']['reported'] is False:
            return '/mock/telemetry'

    return mock_shadow['state']['reported']['pub_topic']


def get_telemetry():
    return json.dumps([
        {
            "version": "2017-05-08",
            "deviceId": "mock-01",
            "data": [
                {
                    "sensorId": "fake_temperature_01",
                    "ts": "{0}".format(time.time()),
                    "value": mock_temp()
                },
                {
                    "sensorId": "fake_temperature_02",
                    "ts": "{0}".format(time.time()),
                    "value": mock_temp()
                }
            ]
        },
        {
            "version": "2017-05-08",
            "deviceId": "mock-02",
            "data": [
                {
                    "sensorId": "fake_voltage_01",
                    "ts": "{0}".format(time.time()),
                    "value": mock_voltage()
                },
                {
                    "sensorId": "fake_amperage_01",
                    "ts": "{0}".format(time.time()),
                    "value": mock_amperage()
                }
            ]

        }
    ])


def publish_telemetry(mock_shadow):
    response = gg_client.publish(
        topic=get_pub_topic(mock_shadow),
        qos=0,
        payload=get_telemetry()
    )
    print("[publish_telemetry] publish resp:{0}".format(response))


def run_mock():
    mock_shadow = get_shadow_state()
    while True:
        for count, element in enumerate(range(10), 1):  # Start count from 1
            publish_telemetry(mock_shadow)
            time.sleep(get_pub_frequency(mock_shadow))
            if count % 10 == 0:  # every 10 times through, update mock_shadow
                mock_shadow = get_shadow_state()

run_mock()


# Handler for processing lambda events
def handler(event, context):
    # Unwrap the message
    msg = json.loads(event)
    logging.info("[handler] thinking about message: {0}".format(msg))

    # publish some telemetry
    mock_shadow = get_shadow_state()
    publish_telemetry(mock_shadow)