#ifdef CONFIG_HIP_MIDAUTH
static char *midauth_cert="(sequence (public_key (rsa-pkcs1-sha1 (e #010001#) \
(n |n1CheoELqYRSkHYMQddub2TpILl+6H9wC/as6zFCZqOY43hsZgAjG0F\
GoQwtyOyQjzO2Ykb2TmUCZemTYui/sR0zIbdwg1xafKl7ggZDkhk5an\
PtGDxJxFalTYo6/A5ZQv8uatbaJgB/G7VM8G+O9HLucadad2zQUXpQf\
gbK3S8=|)))(cert (issuer (hash hit 2001:0014:06cf:fae7:bb79:bf78:7d64:c056)\
)(subject (hash hit 2001:0014:06cf:fae7:bb79:bf78:7d64:c056))\
(not-before \"2008-07-12_22:11:07\")(not-after \"2008-07-22_22:11:07\")\
)(signature (hash sha1 |kfElDhagiK0Bsqtj32Gq3t/1mxgA|)\
|HiIqjjZIUzypvoxQyO0UovPm5uC4Xte0scEcBnENDIfn2DNy/bAtxGEdKq4O\
dW80vTCmkF8/HXclgXLLVch3DxRNdSbYiiks000HpQt/OKqlTH+uUHBcHOAo\
E42LmDskM9T5KQJoC/CH7871zfvojPnpkl2dUngOWv4q0r/wSJ0=|))";

char *hip_pisa_get_certificate(void)
{
	return midauth_cert;
}
#endif
