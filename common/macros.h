/*
 * useful macros (and small funcs)
 */
#pragma once


void error_kill(const char *file, int lineno, const char *msg);
void error_log(const char *file, int lineno, const char *msg);
void die(const char *msg);

#define LOG_KILL(msg) error_kill(__FILE__, __LINE__, msg)
#define LOG(msg) error_kill(__FILE__, __LINE__, msg)
#define DEFAULT_BUF_SIZE (1<<10)
