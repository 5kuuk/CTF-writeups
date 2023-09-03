# Safe Calculator
```
1. Use the safe calculator
2. Review the safe calculator
>
```
Let's check the decompilation (ghidra) :
```C
void calculate(void)

{
  long in_FS_OFFSET;
  long local_28;
  long local_20;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_sscanf(sum,"{ arg1: %d, arg2: %d}",&local_28,&local_20);
  local_18 = local_20 + local_28;
  printf("The result of the sum is: %d, it\'s over 9000!\n",local_18);
  if (local_18 == -0x4673a0c8ffffdcd7) {
    puts("That is over 9000 indeed, how did you do that?");
    win();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void leave_review(void)

{
  long in_FS_OFFSET;
  undefined local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enjoyed our calculator? Leave a review! : ");
  __isoc99_scanf("%48[ -~]",local_48);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void win(void)

{
  system("/bin/sh");
  return;
}

void main(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("1. Use the safe calculator");
  puts("2. Review the safe calculator");
  while( true ) {
    while( true ) {
      printf("> ");
      __isoc99_scanf(&DAT_00102110,&local_14);
      getchar();
      if (local_14 != 1) break;
      calculate();
    }
    if (local_14 != 2) break;
    leave_review();
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
So we need to pass the check in calculate to call `win()`.
At first glance, we have no control over `a` and `b` (they are read from the program's data, and sum to `9001`) and it looks like the check must fail.
With a closer look you can see that `a` and `b` are loaded as `int` and not as `long`, so the upper 4 bytes of each is not set.
Also, the locals in `calculate` will overlap with the previous locals of `leav_review` on the stack, if we calculate after leaving a review.
We just need to set the part of the string which overlap with a and b accordingly for the sum to match !
However, when leaving a review, we are constrained to only characters whose ascii representation is between that of '_' and that of '~' *(check the [scanf manpage](https://man7.org/linux/man-pages/man3/scanf.3.html))*.

Thus, we need to generate valid characters for the sum to match, byte by byte. There is an issue with the 0x37 (which itself correspond to a valid char) byte which we cannot compute as a sum of those valid characters. However, since scanf adds a null byte at the end, by leaving a second review, we can insert a null byte at the adequate position in `b`, corresponding at the position of 0x37 in `a` !
