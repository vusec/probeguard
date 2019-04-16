struct pt_insn_decoder;
struct pt_config;
struct pt_image;
void load_sideband(char *fn, struct pt_image *image, struct pt_config *config);
extern double tsc_freq;
