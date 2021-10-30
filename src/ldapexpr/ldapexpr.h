#ifndef LDAPEXPR_H
#define LDAPEXPR_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

typedef struct filter_st {
	enum {
		FT_EQ,		/* = */
		FT_NE,		/* != */
		FT_LT,		/* < */
		FT_GT,		/* > */
		FT_LTE,		/* <= */
		FT_GTE,		/* >= */
		
		FT_AND,		/* 复合过滤器 & */
		FT_OR,		/* 复合过滤器 | */
		FT_NOT,		/* 复合过滤器 ! */
	} type;
	
	union {
		struct {
			struct filter_st *left;
			struct filter_st *right;
		} m;		/* 复合过滤器时使用 */
		struct {
			char *subject;
			char *value;
		} s;		/* 非复合过滤时使用 */
	};
} filter_st;

extern const char *s_ft_tab[];
// 对外暴露的函数
filter_st *filter_init(const char *filter_str);
void filter_destroy(filter_st *filt);


#endif