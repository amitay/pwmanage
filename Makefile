# Wrapper for waf

WAF = ./waf

all:
	$(WAF) build

clean:
	$(WAF) clean

.PHONY: all clean
