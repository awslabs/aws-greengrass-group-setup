
"""
A mock device Lambda that both generates telemetry on a topic and then reviews
telemetry it receives for a simple threshold crossing error.
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


def get_pub_frequency(shadow):
    if 'state' in shadow is False or \
        'reported' in shadow['state'] is False or \
            'pub_frequency' in shadow['state']['reported'] is False:
            return 1

    return shadow['state']['reported']['pub_frequency']


def get_error_topic(shadow):
    if 'state' in shadow is False or \
        'reported' in shadow['state'] is False or \
            'error_topic' in shadow['state']['reported'] is False:
            return '/errors'

    return shadow['state']['reported']['error_topic']


def get_pub_topic(shadow):
    if 'state' in shadow is False or \
        'reported' in shadow['state'] is False or \
            'pub_topic' in shadow['state']['reported'] is False:
            return '/telemetry'

    return shadow['state']['reported']['pub_topic']


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


def publish_telemetry(shadow):
    response = gg_client.publish(
        topic=get_pub_topic(shadow),
        qos=0,
        payload=get_telemetry()
    )
    print("[publish_telemetry] publish resp:{0}".format(response))


def publish_error(shadow, error):
    response = gg_client.publish(
        topic=get_error_topic(shadow),
        qos=0,
        payload=error
    )
    print("[publish_telemetry] publish resp:{0}".format(response))


def run_mock():
    shadow = get_shadow_state()
    while True:
        for count, element in enumerate(range(10), 1):  # Start count from 1
            publish_telemetry(shadow)
            time.sleep(get_pub_frequency(shadow))
            if count % 10 == 0:  # every 10 times through, update shadow
                shadow = get_shadow_state()

run_mock()


# Handler for processing Lambda events
# this function should be subscribed to pub_topic
def handler(event, context):
    # Unwrap the message
    msg = json.loads(event)
    logging.info("[handler] thinking about message: {0}".format(msg))

    error_val = None
    for item in msg:
        if item['device'] is 'mock-01':
            for d in item['data']:
                if d['value'] > 70:
                    error_val = d['value']
                    break
    if error_val:
        publish_error(
            get_shadow_state(),
            json.dumps({
                "error_message": "found an error in telemetry",
                "error_value": error_val
            })
        )
    else:
        logging.info("[handler] no error found.")
