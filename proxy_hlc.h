#ifndef PROXY_HLC_H
#define PROXY_HLC

int mcplib_global_hlc_gc(lua_State *L);
int mcplib_proxy_hlc_gc(lua_State *L);
int mcp_proxy_hlc(lua_State *from, lua_State *to);
int mcplib_global_hlc(lua_State *L);
int mcplib_proxy_hlc_time(lua_State *L);
int mcplib_proxy_hlc_time_string(lua_State *L);
int mcplib_proxy_hlc_add_to_req(lua_State *L);
int mcplib_proxy_hlc_get_from_res(lua_State *L);
int mcplib_proxy_hlc_get_from_req(lua_State *L);

#endif
