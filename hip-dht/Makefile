DIRS = share clientlib  dnsd  tracker
all:
	for subdir in $(DIRS); do \
          echo "Making all in $$subdir"; \
          if test "$$subdir" != "."; then \
          	(cd $$subdir && $(MAKE) all) \
          fi; \
        done 

clean:
	for subdir in $(DIRS); do \
          echo "Making clean in $$subdir"; \
          if test "$$subdir" != "."; then \
          	(cd $$subdir && $(MAKE) clean) \
          fi; \
        done 
