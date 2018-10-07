/*	Author:  barbarisch, b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#ifndef _MAIN_H_
#define _MAIN_H_


/*
 * Struct for the rules
 */
typedef struct {

    LPCWSTR service_name;                   
	LPCWSTR service_user; 
	LPCWSTR service_password; 

} SVC_STRUCT, *PSVC_STRUCT;












#endif