
# Copyright (C) Ngwsx


default:	clean configure make

configure:
	(cd $(NGINX_DIR); \
	sh configure $(CONF_ARGS); \
	cd $(ADDON_DIR));

make:
	(cd $(NGINX_DIR); \
	$(MAKE) -f $(ADDON_DIR)/build/Makefile; \
	cd $(ADDON_DIR); \
	mv build/nginx build/$(NGINX_BIN));

clean:
	(cd $(NGINX_DIR); \
	rm -rf Makefile $(ADDON_DIR)/build; \
	cd $(ADDON_DIR));

install:
	(cd $(NGINX_DIR); \
	$(MAKE) -f $(ADDON_DIR)/build/Makefile install; \
	cd $(ADDON_DIR));
