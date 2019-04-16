/************************************************
 * Description :
   	Header shared by the remorpher
 	and the analyzer

   Author      : Koustubha Bhat
   Date	       : 11-May-2016
   Vrije Universiteit Amsterdam, The Netherlands.
 ************************************************/

#ifndef RDEFENDER_H
#define RDEFENDER_H

#include "rdiag.h"

#define RDEF_INIT_TYPE_MAIN	0
#define RDEF_INIT_TYPE_THREAD	1

// Publicly interfacing functions
extern pid_t rdf_pid;

//int rdef_init(char **argv);   // hook that is called in by the target server app. (maybe right in main())
int rdef_init();   // hook that is called in by the target server app. (maybe right in main())
int rdef_on_detect();           // hook that is called in by the target server app. (by the signal handler for SIGCHLD or when it would be respawned.)
// int rdef_control(/* TODO: Decide what all controls and how to handle them */);

#endif
