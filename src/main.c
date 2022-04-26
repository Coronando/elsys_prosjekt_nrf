/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <net/socket.h>
#include <modem/nrf_modem_lib.h>
#include <net/tls_credentials.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <stdio.h>
#include <drivers/adc.h>
#include <date_time.h>

const struct device *adc_dev;

#include <hal/nrf_saadc.h>
#define ADC_DEVICE_NAME DT_ADC_0_NAME
#define ADC_RESOLUTION 10
#define ADC_GAIN ADC_GAIN_1_6
#define ADC_REFERENCE ADC_REF_INTERNAL
#define ADC_ACQUISITION_TIME ADC_ACQ_TIME(ADC_ACQ_TIME_MICROSECONDS, 10)
#define ADC_1ST_CHANNEL_ID 0
#define ADC_1ST_CHANNEL_INPUT NRF_SAADC_INPUT_AIN0
#define ADC_2ND_CHANNEL_ID 2
#define ADC_2ND_CHANNEL_INPUT NRF_SAADC_INPUT_AIN2

static const struct adc_channel_cfg m_1st_channel_cfg = {
	.gain = ADC_GAIN,
	.reference = ADC_REFERENCE,
	.acquisition_time = ADC_ACQUISITION_TIME,
	.channel_id = ADC_1ST_CHANNEL_ID,
#if defined(CONFIG_ADC_CONFIGURABLE_INPUTS)
	.input_positive = ADC_1ST_CHANNEL_INPUT,
#endif
};

#define BUFFER_SIZE 8
static int16_t m_sample_buffer[BUFFER_SIZE];

const struct adc_sequence_options sequence_opts = {
	.interval_us = 0,
	.callback = NULL,
	.user_data = NULL,
	.extra_samplings = 7,
};

static void adc_sample(void)
{	
	float threshold = 1700;
	float max_val = 0;
	const struct adc_sequence sequence = {
		.options = &sequence_opts,
		.channels = BIT(ADC_1ST_CHANNEL_ID),
		.buffer = m_sample_buffer,
		.buffer_size = sizeof(m_sample_buffer),
		.resolution = ADC_RESOLUTION,
	};

	if (!adc_dev) {
		return -1;
	}
	while(true){
		int ret;

		//Fetches the values in the adc buffer
		ret = adc_read(adc_dev, &sequence);

		//Itterates over the adc values
		for (int i = 0; i < BUFFER_SIZE; i++) {
			float adc_voltage = 0;
			adc_voltage = (float)(((float)m_sample_buffer[i] / 1023.0f) *
						3600.0f);
			// if(adc_voltage >= max_val){
			// 	max_val = adc_voltage;
			// 	//printk("Value: %f ", max_val);
			// }
			//If the value exceeds the threshold the the function returns
			if(adc_voltage >= threshold){
				return;
			}
		}

	}
}
#define HTTPS_PORT 443

#define HTTPS_HOSTNAME "gruppe14.innovasjon.ed.ntnu.no"

#define HTTP_HEAD                                           \
	"POST /map/sample/ HTTP/1.1\r\n"  						\
	"Host: " HTTPS_HOSTNAME ":443\r\n"						\
	"Connetion: close\r\n"							\
	"Content-Type: application/json\r\n"					\
	"Content-Length: 27 \r\n\r\n"							\
	"{\"node\": 1, \"level\": \"100\"}"	

#define HTTP_HEAD2  	                                    \
	"POST /map/sample/ HTTP/1.1\r\n"  						\
	"Host: " HTTPS_HOSTNAME ":443\r\n"						\
	"Connetion: close\r\n"									\
	"Content-Type: application/json\r\n"					\
	"Content-Length: 27 \r\n\r\n"							\
	"{\"node\": 1, \"level\": \"%i\"}"	

#define HTTP_HEAD_LEN (sizeof(HTTP_HEAD) - 1)
#define HTTP_HDR_END "\r\n\r\n"
#define RECV_BUF_SIZE 2048
#define TLS_SEC_TAG 42

char send_buf[171];
static char recv_buf[RECV_BUF_SIZE];


static const char cert[] = {
	#include "../cert/CertElsys3.cert"
};

BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");

/* Provision certificate to modem */
int cert_provision(void)
{
	int err;
	bool exists;
	int mismatch;

	/* It may be sufficient for you application to check whether the correct
	 * certificate is provisioned with a given tag directly using modem_key_mgmt_cmp().
	 * Here, for the sake of the completeness, we check that a certificate exists
	 * before comparing it with what we expect it to be.
	 */
	err = modem_key_mgmt_exists(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, &exists);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		mismatch = modem_key_mgmt_cmp(TLS_SEC_TAG,
					      MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
					      cert, strlen(cert));
		if (!mismatch) {
			printk("Certificate match\n");
			return 0;
		}

		printk("Certificate mismatch\n");
		err = modem_key_mgmt_delete(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n", err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

#if defined(CONFIG_SAMPLE_TFM_MBEDTLS)
	err = tls_credential_add(tls_sec_tag[0], TLS_CREDENTIAL_CA_CERTIFICATE, cert, sizeof(cert));
	if (err) {
		return err;
	}
#endif

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, HTTPS_HOSTNAME, sizeof(HTTPS_HOSTNAME) - 1);
	if (err) {
		printk("Failed to setup TLS hostname, err %d\n", errno);
		return err;
	}
	return 0;
}

void setup_adc(){
	int err;

	printk("nRF53 SAADC sampling AIN0 (P0.13)\n");

	adc_dev = device_get_binding("ADC_0");
	if (!adc_dev) {
		printk("device_get_binding ADC_0 failed\n");
		printk("Error: %d", adc_dev);
	}
	err = adc_channel_setup(adc_dev, &m_1st_channel_cfg);
	if (err) {
		printk("Error in adc setup: %d\n", err);
	}

	/* Trigger offset calibration
	 * As this generates a _DONE and _RESULT event
	 * the first result will be incorrect.
	 */
	NRF_SAADC_NS->TASKS_CALIBRATEOFFSET = 1;
	
}

void main(void)
{
	int err;
	int fd;
	char *p;
	int bytes;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	printk("HTTPS client sample started\n\r");

#if !defined(CONFIG_SAMPLE_TFM_MBEDTLS)
	/* Provision certificates before connecting to the LTE network */
	err = cert_provision();
	if (err) {
		return;
	}
#endif

	printk("Waiting for network.. ");
	err = lte_lc_init_and_connect();
	if (err) {
		printk("Failed to connect to the LTE network, err %d\n", err);
		return;
	}
	printk("OK\n");
	printk("Setting up adc...\n");
	setup_adc();
	printk("Setup done!\n");
	
	// int64_t current_time;
	// date_time_set(&current_time);

	// printk(current_time);

	// date_time_now(&current_time);

	// printk(current_time);
	while(true){
			printk("Entering measuring state\n");
			adc_sample();
			printk("Leaving measuring state\n");
			err = getaddrinfo(HTTPS_HOSTNAME, NULL, &hints, &res);
			if (err) {
				printk("getaddrinfo() failed, err %d\n", errno);
				return;
			}

			((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);

			if (IS_ENABLED(CONFIG_SAMPLE_TFM_MBEDTLS)) {
				fd = socket(AF_INET, SOCK_STREAM | SOCK_NATIVE_TLS, IPPROTO_TLS_1_2);
			} else {
				fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
			}
			if (fd == -1) {
				printk("Failed to open socket!\n");
				goto clean_up;
			}

			/* Setup TLS socket options */
			err = tls_setup(fd);
			if (err) {
				goto clean_up;
			}

			printk("Connecting to %s\n", HTTPS_HOSTNAME);
			err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
			if (err) {
				printk("connect() failed, err: %d\n", errno);
				goto clean_up;
			}
			
			sprintf(send_buf, HTTP_HEAD2, 666);
			//printk((int)sizeof(send_buf));
			//size_t HTTP_HEAD_LEN2 = (strlen(send_buf) - 1);
			//#define HTTP_HEAD_LEN (sizeof(HTTP_HEAD) - 1)
			//printk(HTTP_HEAD_LEN2);
			//printk(HTTP_HEAD_LEN);
			off = 0;
			do {
				bytes = send(fd, &send_buf[off], sizeof(HTTP_HEAD) - 1, 0);
				if (bytes < 0) {
					printk("send() failed, err %d\n", errno);
					goto clean_up;
				}
				off += bytes;
			} while (off < HTTP_HEAD_LEN);

			printk("Sent %d bytes\n", off);

			off = 0;
			do {
				bytes = recv(fd, &recv_buf[off], RECV_BUF_SIZE - off, 0);
				if (bytes < 0) {
					printk("recv() failed, err %d\n", errno);
					goto clean_up;
				}
				off += bytes;
			} while (bytes != 0 /* peer closed connection */);

			printk("Received %d bytes\n", off);

			/* Print HTTP response */
			p = strstr(recv_buf, "\r\n");
			if (p) {
				off = p - recv_buf;
				recv_buf[off + 1] = '\0';
				printk("\n>\t %s\n\n", recv_buf);
			}

			printk("Finished, closing socket.\n");
		

		clean_up:
			freeaddrinfo(res);
			(void)close(fd);
		while(true){
			NULL;
		}
	}
	lte_lc_power_off();
}
