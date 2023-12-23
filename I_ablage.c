//
// Created by rigon on 23.12.23.
//
int main() {
    //char* p = verifier_nondet_string();
    uint32_t u = __VERIFIER_nondet_uint();

    unsigned char strlength = __VERIFIER_nondet_char();

    char* str = (char*)malloc(strlength + 1);
    //for(int i = 0; i < strlength; i++){
    //    str[i] = __VERIFIER_nondet_char();
    //}
    //str[strlength] = '\0';

    printf("uint32_t: %u, String: %s\n", u, str);

    itoa_u32(u, str);

    free(str);
    return 1;
}