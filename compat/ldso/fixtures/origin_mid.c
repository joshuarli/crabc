extern int origin_leaf(void);

int origin_mid(void)
{
    return origin_leaf() + 1;
}
