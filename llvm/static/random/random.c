#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define STATELEN        32
#define SEED		0x7ECCE2
#define SWITCHBOARD_SIZE	32000

static uint64_t flag_access_board[SWITCHBOARD_SIZE] = { 0, };

int prand(unsigned p)
{
  static unsigned initialized = 0;
  int32_t rnum = 0;
  int ret=0, r=0;
  static char statebuf[STATELEN];
  static struct random_data rdata;
  
  if (!initialized) {
        initstate_r(SEED, &statebuf[0], STATELEN, &rdata);
	initialized = 1;
  }
  ret = random_r(&rdata, &rnum);
  assert(ret == 0);
//  if (ret != 0) rnum = 90;
  r = rnum % 100;
 
  if (r <= p)
  {
        return 1;
  }
  else
  {
        return 0;
  }
}

void log_flags_access(unsigned flag_id)
{
    FILE *fp = NULL;
    
    assert(flag_id < SWITCHBOARD_SIZE);
    if (0 == flag_access_board[flag_id]) 
    	printf("bbclone switchboard : flag accessed: %u\n", flag_id);

    flag_access_board[flag_id]++;
    fp = fopen("./nginx.funcfreq.log", "w+");
    for (uint64_t i = 1; i < 1160; i++) {
	fprintf(fp, "flag_id: %u count: %u\n", i, flag_access_board[i]);
    }
    fclose(fp);
}
