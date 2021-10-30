/* 一个简单的递归向下ldap filter表达式分析器 */
#include "ldapexpr.h"

const char *s_ft_tab[] = {
	"=",
	"!=",
	"<",
	">",
	"<=",
	">=",
	"and",
	"or",
	"not",
};

static int opr2type(const char *opr)
{
	if (strcmp(opr, "=") == 0)
		return FT_EQ;
	
	if (strcmp(opr, "!=") == 0)
		return FT_NE;
	
	if (strcmp(opr, "<") == 0)
		return FT_LT;
	
	if (strcmp(opr, ">") == 0)
		return FT_GT;
	
	if (strcmp(opr, "<=") == 0)
		return FT_LTE;
	
	if (strcmp(opr, ">=") == 0)
		return FT_GTE;
	
	return -1;
}

static filter_st *filter_create(int ft)
{
	filter_st *ret = calloc(1, sizeof(filter_st));
	assert(ret);
	
	ret->type = ft;
	return ret;
}

void filter_destroy(filter_st *filt)
{
	if (!filt)
		return;
	
	if (filt->type == FT_AND || filt->type == FT_OR || filt->type == FT_NOT) {
		filter_destroy(filt->m.left);
		filter_destroy(filt->m.right);
	} else {
		free(filt->s.subject);
		free(filt->s.value);
	}
	
	free(filt);
}

/* 处理txt，起始位置为*pos，完成后*pos应指向未parse的新位置 */
static filter_st *filter_parse_(const char *txt, uint32_t *pos)
{
	filter_st *ret = NULL;
	char subject[128];
	char value[128];
	char opr[16];
	
	/* 所有filter都是(开始 */
	if (txt[*pos] != '(') {
		fprintf(stderr, "Filter expect a '('\n");
		return NULL;
	}
	
	(*pos)++;
	switch (txt[*pos]) {
	case '&':
	case '|':
		/* (&(X)(Y)) and or表过式第一个字符为&|，后面带两个子表达式，递归处理并赋值到left/right */
		ret = filter_create(txt[*pos] == '&' ? FT_AND : FT_OR);
		
		(*pos)++;
		
		ret->m.left = filter_parse_(txt, pos);
		if (!ret->m.left)
			goto failed;
		
		ret->m.right = filter_parse_(txt, pos);
		if (!ret->m.right)
			goto failed;
		
		break;
	case '!':
		/* (!(X)) not表达式第一个字符为!，后面带一个子表达式，存于left */
		ret = filter_create(FT_NOT);
		
		(*pos)++;
		
		ret->m.left = filter_parse_(txt, pos);
		if (!ret->m.left)
			goto failed;
		
		break;
	default:
		/* (subject?=value) 普通表达式，简单地使用sscanf获取数据 */
		if (sscanf(txt + *pos, "%127[^=!<>()\n ]%15[=!<>]%127[^)]", subject, opr, value) != 3) {
			fprintf(stderr, "Filter format error\n");
			goto failed;
		}
		
		int type = opr2type(opr);
		if (type < 0) {
			fprintf(stderr, "Filter operator not supported: %s\n", opr);
			goto failed;
		}
		
		/* 定位到当前表达式的)处 */
		const char *end = strchr(txt + *pos, ')');
		if (!end) {
			fprintf(stderr, "Filter is not closed with ')'\n");
			goto failed;
		}
		
		ret = filter_create(type);
		ret->s.subject = strdup(subject);
		ret->s.value = strdup(value);
		
		/* 更新*pos为)的位置 */
		*pos = (end - txt);
		break;
	}
	
	/* 所有filter都是)结束 */
	if (txt[*pos] != ')') {
		fprintf(stderr, "Filter expect a '('\n");
		goto failed;
	}
	(*pos)++;
	return ret;
	
failed:
	filter_destroy(ret);
	return NULL;
}

filter_st *filter_init(const char *txt)
{
	uint32_t pos = 0;
	filter_st *filt = filter_parse_(txt, &pos);
	
	if (txt[pos] != 0) {
		fprintf(stderr, "Unexpected %s\n", txt + pos);
		filter_destroy(filt);
		return NULL;
	}
	
	return filt;
}


static void filter_debug_(filter_st *f, int s)
{
	int i;
	for (i = 0; i < s; ++i)
		printf("  ");
	
	printf("%s", s_ft_tab[f->type]);
	if (f->type == FT_AND || f->type == FT_OR) {
		printf("\n");
		filter_debug_(f->m.left, s + 1);
		filter_debug_(f->m.right, s + 1);
	} else if (f->type == FT_NOT) {
		printf("\n");
		filter_debug_(f->m.left, s + 1);
	} else {
		printf(" %s %s\n", f->s.subject, f->s.value);
	}
}

/* 查看filter */
void filter_debug(filter_st *filt)
{
	filter_debug_(filt, 0);
}

