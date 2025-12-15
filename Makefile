# Build everything
all: meson.build
	rm -rf build
	meson setup build
	ninja -C build

# Run Flask and l2fwd only if not already running
run: ./build/l2fwd
	sudo ./build/l2fwd -l 0-15 -n 4 -- -q 1 -p 0x3 -P --no-mac-updating
	
# Run l2fwd under gdb
run_gdb: ./build/l2fwd
	sudo gdb --args ./build/l2fwd -l 0-15 -n 4 -- -q 1 -p 0x3 -P --no-mac-updating

# Clean up
clean:
	rm -rf build
