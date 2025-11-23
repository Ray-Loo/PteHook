#pragma once
#define CRLF " \r\n"
#define SKIP "  "
#define Dbg(content , ...)   DbgPrintEx (77,0,SKIP content, __VA_ARGS__)
#define Dbgf(content , ...)  DbgPrintEx (77,0, __FUNCTION__     "[>]"  SKIP content  CRLF, __VA_ARGS__)