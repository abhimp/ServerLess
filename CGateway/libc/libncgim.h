/*
 * libncgi.h
 *
 *  Created on: Jul 19, 2020
 *      Author: abhijit
 */

#ifndef LIBC_LIBNCGIM_H_
#define LIBC_LIBNCGIM_H_


//void *ncgimInitServer();
void ncgimRunForever(void (*handler)(void));

#endif /* LIBC_LIBNCGIM_H_ */
