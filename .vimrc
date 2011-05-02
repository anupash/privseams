" indentation rules for HIPL: 4 spaces, no tabs
set expandtab
set shiftwidth=4
set tabstop=4

autocmd FileType make,automake set noexpandtab shiftwidth=8 tabstop=8

" trailing whitespace is forbidden, so highlight it
let c_space_errors = 1
