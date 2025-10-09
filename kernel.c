#include "kernel.h"
#include "common.h"

// --- Global Data ---
// Process table and process management pointers
struct process procs[PROCS_MAX];
struct process *current_proc;
struct process *idle_proc;

// Symbols from the linker script, defining memory layout
extern char __bss[], __bss_end[];
extern char __free_ram[], __free_ram_end[];
extern char __kernel_base[];
extern char __stack_top[];

// symbols for embedded shell binary
extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

// --- Forward Declarations ---
void kernel_entry(void);
void handle_trap(struct trap_frame *f);

// --- Boot and Low-Level Entry ---

// The boot function, the very first code to run in machine mode.
// It sets up the stack and jumps to kernel_main.
__attribute__((section(".text.boot"))) __attribute__((naked)) void boot(void) {
  __asm__ __volatile__("mv sp, %[stack_top]\n\t"
                       "j kernel_main"
                       :
                       : [stack_top] "r"(__stack_top));
}

// The kernel_entry function, the entry point for all traps.
// It saves the context, calls the trap handler, and restores the context.
__attribute__((naked)) __attribute__((aligned(4))) void kernel_entry(void) {
  __asm__ __volatile__(
      // Save all general-purpose registers
      "csrrw sp, sscratch, sp\n\t"
      "addi sp, sp, -4 * 31\n\t"
      "sw ra,  4 * 0(sp)\n\t"
      "sw gp,  4 * 1(sp)\n\t"
      "sw tp,  4 * 2(sp)\n\t"
      "sw t0,  4 * 3(sp)\n\t"
      "sw t1,  4 * 4(sp)\n\t"
      "sw t2,  4 * 5(sp)\n\t"
      "sw t3,  4 * 6(sp)\n\t"
      "sw t4,  4 * 7(sp)\n\t"
      "sw t5,  4 * 8(sp)\n\t"
      "sw t6,  4 * 9(sp)\n\t"
      "sw a0,  4 * 10(sp)\n\t"
      "sw a1,  4 * 11(sp)\n\t"
      "sw a2,  4 * 12(sp)\n\t"
      "sw a3,  4 * 13(sp)\n\t"
      "sw a4,  4 * 14(sp)\n\t"
      "sw a5,  4 * 15(sp)\n\t"
      "sw a6,  4 * 16(sp)\n\t"
      "sw a7,  4 * 17(sp)\n\t"
      "sw s0,  4 * 18(sp)\n\t"
      "sw s1,  4 * 19(sp)\n\t"
      "sw s2,  4 * 20(sp)\n\t"
      "sw s3,  4 * 21(sp)\n\t"
      "sw s4,  4 * 22(sp)\n\t"
      "sw s5,  4 * 23(sp)\n\t"
      "sw s6,  4 * 24(sp)\n\t"
      "sw s7,  4 * 25(sp)\n\t"
      "sw s8,  4 * 26(sp)\n\t"
      "sw s9,  4 * 27(sp)\n\t"
      "sw s10, 4 * 28(sp)\n\t"
      "sw s11, 4 * 29(sp)\n\t"

      // Save the original stack pointer
      "csrr a0, sscratch\n\t"
      "sw a0,  4 * 30(sp)\n\t"

      // Set sscratch to the kernel stack for the trap handler
      "addi a0, sp, 4 * 31\n\t"
      "csrw sscratch, a0\n\t"

      // Call the C trap handler
      "mv a0, sp\n\t"
      "call handle_trap\n\t"

      // Restore all general-purpose registers
      "lw ra,  4 * 0(sp)\n\t"
      "lw gp,  4 * 1(sp)\n\t"
      "lw tp,  4 * 2(sp)\n\t"
      "lw t0,  4 * 3(sp)\n\t"
      "lw t1,  4 * 4(sp)\n\t"
      "lw t2,  4 * 5(sp)\n\t"
      "lw t3,  4 * 6(sp)\n\t"
      "lw t4,  4 * 7(sp)\n\t"
      "lw t5,  4 * 8(sp)\n\t"
      "lw t6,  4 * 9(sp)\n\t"
      "lw a0,  4 * 10(sp)\n\t"
      "lw a1,  4 * 11(sp)\n\t"
      "lw a2,  4 * 12(sp)\n\t"
      "lw a3,  4 * 13(sp)\n\t"
      "lw a4,  4 * 14(sp)\n\t"
      "lw a5,  4 * 15(sp)\n\t"
      "lw a6,  4 * 16(sp)\n\t"
      "lw a7,  4 * 17(sp)\n\t"
      "lw s0,  4 * 18(sp)\n\t"
      "lw s1,  4 * 19(sp)\n\t"
      "lw s2,  4 * 20(sp)\n\t"
      "lw s3,  4 * 21(sp)\n\t"
      "lw s4,  4 * 22(sp)\n\t"
      "lw s5,  4 * 23(sp)\n\t"
      "lw s6,  4 * 24(sp)\n\t"
      "lw s7,  4 * 25(sp)\n\t"
      "lw s8,  4 * 26(sp)\n\t"
      "lw s9,  4 * 27(sp)\n\t"
      "lw s10, 4 * 28(sp)\n\t"
      "lw s11, 4 * 29(sp)\n\t"
      "lw sp,  4 * 30(sp)\n\t" // Restore original stack pointer
      "sret");
}

// --- SBI (Supervisor Binary Interface) Calls ---

// Makes a generic SBI call.
struct sbiret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4,
                       long arg5, long fid, long eid) {
  register long a0 __asm__("a0") = arg0;
  register long a1 __asm__("a1") = arg1;
  register long a2 __asm__("a2") = arg2;
  register long a3 __asm__("a3") = arg3;
  register long a4 __asm__("a4") = arg4;
  register long a5 __asm__("a5") = arg5;
  register long a6 __asm__("a6") = fid;
  register long a7 __asm__("a7") = eid;

  __asm__ __volatile__("ecall"
                       : "=r"(a0), "=r"(a1)
                       : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                         "r"(a6), "r"(a7)
                       : "memory");
  return (struct sbiret){.error = a0, .value = a1};
}

// Uses SBI to print a character to the console.
void putchar(char ch) {
  sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}

// Uses SBI to get a character from the console.
long getchar(void) {
  struct sbiret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, 2);
  return ret.error;
}

// --- Context Switching ---

// Switches context from the previous process to the next process.
__attribute__((naked)) void switch_context(uint32_t *prev_sp,
                                           uint32_t *next_sp) {
  __asm__ __volatile__(
      // Save callee-saved registers of the current process.
      "addi sp, sp, -13 * 4\n\t"
      "sw ra,  0  * 4(sp)\n\t"
      "sw s0,  1  * 4(sp)\n\t"
      "sw s1,  2  * 4(sp)\n\t"
      "sw s2,  3  * 4(sp)\n\t"
      "sw s3,  4  * 4(sp)\n\t"
      "sw s4,  5  * 4(sp)\n\t"
      "sw s5,  6  * 4(sp)\n\t"
      "sw s6,  7  * 4(sp)\n\t"
      "sw s7,  8  * 4(sp)\n\t"
      "sw s8,  9  * 4(sp)\n\t"
      "sw s9,  10 * 4(sp)\n\t"
      "sw s10, 11 * 4(sp)\n\t"
      "sw s11, 12 * 4(sp)\n\t"

      // Save the current stack pointer and load the next one.
      "sw sp, (a0)\n\t"
      "lw sp, (a1)\n\t"

      // Restore callee-saved registers of the next process.
      "lw ra,  0  * 4(sp)\n\t"
      "lw s0,  1  * 4(sp)\n\t"
      "lw s1,  2  * 4(sp)\n\t"
      "lw s2,  3  * 4(sp)\n\t"
      "lw s3,  4  * 4(sp)\n\t"
      "lw s4,  5  * 4(sp)\n\t"
      "lw s5,  6  * 4(sp)\n\t"
      "lw s6,  7  * 4(sp)\n\t"
      "lw s7,  8  * 4(sp)\n\t"
      "lw s8,  9  * 4(sp)\n\t"
      "lw s9,  10 * 4(sp)\n\t"
      "lw s10, 11 * 4(sp)\n\t"
      "lw s11, 12 * 4(sp)\n\t"
      "addi sp, sp, 13 * 4\n\t"
      "ret");
}

// Yields the CPU to another runnable process.
void yield(void) {
  // Find a runnable process using a round-robin scheduler.
  struct process *next = idle_proc;
  for (int i = 0; i < PROCS_MAX; i++) {
    struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
    if (proc->state == PROC_RUNNABLE && proc->pid > 0) {
      next = proc;
      break;
    }
  }

  // If no other process is runnable, do nothing.
  if (next == current_proc)
    return;

  // Switch to the new process's page table.
  __asm__ __volatile__(
      "sfence.vma\n\t"
      "csrw satp, %[satp]\n\t"
      "sfence.vma\n\t"
      "csrw sscratch, %[sscratch]"
      :
      : [satp] "r"(SATP_SV32 | ((uint32_t)next->page_table / PAGE_SIZE)),
        [sscratch] "r"((uint32_t)&next->stack[sizeof(next->stack)]));

  // Perform the context switch.
  struct process *prev = current_proc;
  current_proc = next;
  switch_context(&prev->sp, &next->sp);
}

// --- Trap Handling ---

void handle_syscall(struct trap_frame *f) {
  switch (f->a3) {
  case SYS_PUTCHAR:
    putchar(f->a0);
    break;
  case SYS_GETCHAR:
    while (1) {
      long ch = getchar();
      if (ch >= 0) {
        f->a0 = ch;
        break;
      }

      yield();
    }
    break;
  case SYS_EXIT:
    printf("process %d exited\n", current_proc->pid);
    current_proc->state = PROC_EXITED;
    yield();
    PANIC("unreachable");
  }
}

// Handles all traps. In this simple OS, any trap is considered a fatal error.
void handle_trap(struct trap_frame *f) {
  uint32_t scause = READ_CSR(scause);
  uint32_t stval = READ_CSR(stval);
  uint32_t user_pc = READ_CSR(sepc);

  if (scause == SCAUSE_ECALL) {
    handle_syscall(f);
    user_pc += 4;
  } else {
    PANIC("unexpected trap scause=%x, stval=%x, sepc=%x\n", scause, stval,
          user_pc);
  }

  WRITE_CSR(sepc, user_pc);
}

// --- Memory Management ---

// Allocates 'n' pages of physical memory.
paddr_t alloc_pages(uint32_t n) {
  static paddr_t next_paddr = (paddr_t)__free_ram;
  paddr_t paddr = next_paddr;
  next_paddr += n * PAGE_SIZE;

  if (next_paddr > (paddr_t)__free_ram_end)
    PANIC("out of memory");

  memset((void *)paddr, 0, n * PAGE_SIZE);
  return paddr;
}

// Maps a virtual address to a physical address in a page table.
void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
  if (!is_aligned(vaddr, PAGE_SIZE))
    PANIC("unaligned vaddr %x", vaddr);
  if (!is_aligned(paddr, PAGE_SIZE))
    PANIC("unaligned paddr %x", paddr);

  uint32_t vpn1 = (vaddr >> 22) & 0x3ff;
  if ((table1[vpn1] & PAGE_V) == 0) {
    // Allocate a new page for the 2nd level page table if not present.
    uint32_t pt_paddr = alloc_pages(1);
    table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V;
  }

  // Map the page in the 2nd level page table.
  uint32_t vpn0 = (vaddr >> 12) & 0x3ff;
  uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE);
  table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

// --- Process Management ---

// Entry point for user processes.
__attribute__((naked)) void user_entry(void) {
  __asm__ __volatile__("csrw sepc, %[sepc]        \n"
                       "csrw sstatus, %[sstatus]  \n"
                       "sret                      \n"
                       :
                       : [sepc] "r"(USER_BASE), [sstatus] "r"(SSTATUS_SPIE));
}

// Creates a new process with its own stack and page table.
struct process *create_process(const void *image, size_t image_size) {
  struct process *proc = NULL;
  int i;
  for (i = 0; i < PROCS_MAX; i++) {
    if (procs[i].state == PROC_UNUSED) {
      proc = &procs[i];
      break;
    }
  }

  if (!proc)
    PANIC("no free process slots");

  // Set up the initial stack with callee-saved registers.
  uint32_t *sp = (uint32_t *)&proc->stack[sizeof(proc->stack)];
  *--sp = 0;                    // s11
  *--sp = 0;                    // s10
  *--sp = 0;                    // s9
  *--sp = 0;                    // s8
  *--sp = 0;                    // s7
  *--sp = 0;                    // s6
  *--sp = 0;                    // s5
  *--sp = 0;                    // s4
  *--sp = 0;                    // s3
  *--sp = 0;                    // s2
  *--sp = 0;                    // s1
  *--sp = 0;                    // s0
  *--sp = (uint32_t)user_entry; // ra (return address)

  // Allocate and map the page table.
  uint32_t *page_table = (uint32_t *)alloc_pages(1);

  // map the kernel pages (identity mapping)
  for (paddr_t paddr = (paddr_t)__kernel_base; paddr < (paddr_t)__free_ram_end;
       paddr += PAGE_SIZE)
    map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);

  // Map user pages.
  if (image_size > 0) {
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
      paddr_t page = alloc_pages(1);

      // Handle the case where the data to be copied is smaller than the
      // page size.
      size_t remaining = image_size - off;
      size_t copy_size = PAGE_SIZE <= remaining ? PAGE_SIZE : remaining;

      // Fill and map the page.
      memcpy((void *)page, image + off, copy_size);
      map_page(page_table, USER_BASE + off, page,
               PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }
  }

  // Initialize process fields.
  proc->pid = i + 1;
  proc->state = PROC_RUNNABLE;
  proc->sp = (uint32_t)sp;
  proc->page_table = page_table;
  return proc;
}

// --- Kernel Main ---

// The main C entry point for the kernel.
void kernel_main(void) {
  // Clear the BSS section.
  memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);

  printf("\n\nStarting kernel...\n");

  // Set the trap vector.
  WRITE_CSR(stvec, (uint32_t)kernel_entry);

  // Create the idle process.
  idle_proc = create_process(NULL, 0);
  idle_proc->pid = 0; // pid=0 means idle
  current_proc = idle_proc;

  // Create the shell process.
  create_process(_binary_shell_bin_start, (size_t)_binary_shell_bin_size);

  // Start the scheduler.
  yield();

  // This should not be reached.
  PANIC("switched to idle process");
}
