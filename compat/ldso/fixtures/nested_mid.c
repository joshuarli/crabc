/* The middle DSO deliberately has its own DT_NEEDED edge to nested_leaf. */
extern int nested_leaf_value(void);

int nested_mid_value(void)
{
    return nested_leaf_value() + 1;
}
