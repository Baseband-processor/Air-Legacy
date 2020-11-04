char* append_and_free(char* s1, char *s2, int who) {
	char *new = append(s1, s2);
	if(who & 1) free(s1);
	if(who & 2) free(s2);
	return new;
}

char *wps_data_to_json(const char*bssid, const char *ssid, int channel, int rssi, const unsigned char* vendor, struct libwps_data *wps, const char *progress) {
	size_t ol = 0, nl = 0, ns = 0;
	char *json_str = 0, *old = strdup("{"), *tmp;
	char buf[1024];

	nl = snprintf(buf, sizeof buf, "\"bssid\" : \"%s\", ", bssid);
	json_str = append_and_free(old, buf, 1);
	old = json_str;

	tmp = sanitize_string(ssid);
	nl = snprintf(buf, sizeof buf, "\"essid\" : \"%s\", ", tmp);
	free(tmp);
	json_str = append_and_free(old, buf, 1);
	old = json_str;

	nl = snprintf(buf, sizeof buf, "\"channel\" : %d, ", channel);
	json_str = append_and_free(old, buf, 1);
	old = json_str;

	nl = snprintf(buf, sizeof buf, "\"rssi\" : %d, ", rssi);
	json_str = append_and_free(old, buf, 1);
	old = json_str;

	if(vendor) {
		nl = snprintf(buf, sizeof buf, "\"vendor_oui\" : \"%02X%02X%02X\", ", vendor[0], vendor[1], vendor[2]);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}

	if(wps->version) {
		nl = snprintf(buf, sizeof buf, "\"wps_version\" : %d, ", wps->version);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(wps->state) {
		nl = snprintf(buf, sizeof buf, "\"wps_state\" : %d, ", wps->state);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(wps->locked) {
		nl = snprintf(buf, sizeof buf, "\"wps_locked\" : %d, ", wps->locked);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->manufacturer) {
		tmp = sanitize_string(wps->manufacturer);
		nl = snprintf(buf, sizeof buf, "\"wps_manufacturer\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->model_name) {
		tmp = sanitize_string(wps->model_name);
		nl = snprintf(buf, sizeof buf, "\"wps_model_name\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->model_number) {
		tmp = sanitize_string(wps->model_number);
		nl = snprintf(buf, sizeof buf, "\"wps_model_number\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->device_name) {
		tmp = sanitize_string(wps->device_name);
		nl = snprintf(buf, sizeof buf, "\"wps_device_name\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->ssid) {
		tmp = sanitize_string(wps->ssid);
		nl = snprintf(buf, sizeof buf, "\"wps_ssid\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->serial) {
		tmp = sanitize_string(wps->serial);
		nl = snprintf(buf, sizeof buf, "\"wps_serial\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->os_version) {
		tmp = sanitize_string(wps->os_version);
		nl = snprintf(buf, sizeof buf, "\"wps_os_version\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->uuid) {
		tmp = sanitize_string(wps->uuid);
		nl = snprintf(buf, sizeof buf, "\"wps_uuid\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->selected_registrar) {
		tmp = sanitize_string(wps->selected_registrar);
		nl = snprintf(buf, sizeof buf, "\"wps_selected_registrar\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->response_type) {
		tmp = sanitize_string(wps->response_type);
		nl = snprintf(buf, sizeof buf, "\"wps_response_type\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->primary_device_type) {
		tmp = sanitize_string(wps->primary_device_type);
		nl = snprintf(buf, sizeof buf, "\"wps_primary_device_type\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->config_methods) {
		tmp = sanitize_string(wps->config_methods);
		nl = snprintf(buf, sizeof buf, "\"wps_config_methods\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(*wps->rf_bands) {
		tmp = sanitize_string(wps->rf_bands);
		nl = snprintf(buf, sizeof buf, "\"wps_rf_bands\" : \"%s\", ", tmp);
		free(tmp);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}
	if(progress) {
		nl = snprintf(buf, sizeof buf, "\"progress\" : \"%s\", ", progress);
		json_str = append_and_free(old, buf, 1);
		old = json_str;
	}

	nl = snprintf(buf, sizeof buf, "\"dummy\": 0}");
	json_str = append_and_free(old, buf, 1);

	return json_str;
}
