.PHONY: release clean brunch shadow-cljs uberjar


release: clean brunch shadow-cljs uberjar

clean:
	-rm -r static

brunch:
	bin/brunch build --production

shadow-cljs:
	bin/shadow-cljs release browser

uberjar:
	lein uberjar
