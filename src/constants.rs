pub const BLOCK_SIZE: usize = (u128::BITS as usize) >> 3;
pub const BLOCK_PER_COLUMN: usize = 4;
pub const MATRIX_COLUMNS: usize = BLOCK_SIZE * BLOCK_PER_COLUMN;
pub const MATRIX_ROWS: usize = 256;
pub const MATRIX_SIZE: usize = MATRIX_COLUMNS * MATRIX_ROWS;
