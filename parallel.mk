# If PARALLEL is set and does not contain -j or --jobs, prepend it and export the variable
ifneq ($(strip $(PARALLEL)),)
ifeq ($(filter -j% --jobs%,$(PARALLEL)),)
override PARALLEL := -j $(PARALLEL)
endif
endif
export PARALLEL
