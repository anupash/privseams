/*
 *  linux/include/asm-arm/arch-omap/dma.h
 *
 *  Copyright (C) 2003 Nokia Corporation
 *  Author: Juha Yrj�l� <juha.yrjola@nokia.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __ASM_ARCH_DMA_H
#define __ASM_ARCH_DMA_H

#define MAX_DMA_ADDRESS			0xffffffff

#define OMAP_LOGICAL_DMA_CH_COUNT	17

#define OMAP_DMA_NO_DEVICE		0
#define OMAP_DMA_MCSI1_TX		1
#define OMAP_DMA_MCSI1_RX		2
#define OMAP_DMA_I2C_RX			3
#define OMAP_DMA_I2C_TX			4
#define OMAP_DMA_EXT_NDMA_REQ		5
#define OMAP_DMA_EXT_NDMA_REQ2		6
#define OMAP_DMA_UWIRE_TX		7
#define OMAP_DMA_MCBSP1_DMA_TX		8
#define OMAP_DMA_MCBSP1_DMA_RX		9
#define OMAP_DMA_MCBSP3_DMA_TX		10
#define OMAP_DMA_MCBSP3_DMA_RX		11
#define OMAP_DMA_UART1_TX		12
#define OMAP_DMA_UART1_RX		13
#define OMAP_DMA_UART2_TX		14
#define OMAP_DMA_UART2_RX		15
#define OMAP_DMA_MCBSP2_TX		16
#define OMAP_DMA_MCBSP2_RX		17
#define OMAP_DMA_UART3_TX		18
#define OMAP_DMA_UART3_RX		19
#define OMAP_DMA_CAMERA_IF_RX		20
#define OMAP_DMA_MMC_TX			21
#define OMAP_DMA_MMC_RX			22
#define OMAP_DMA_NAND			23
#define OMAP_DMA_IRQ_LCD_LINE		24
#define OMAP_DMA_MEMORY_STICK		25
#define OMAP_DMA_USB_W2FC_RX0		26
#define OMAP_DMA_USB_W2FC_RX1		27
#define OMAP_DMA_USB_W2FC_RX2		28
#define OMAP_DMA_USB_W2FC_TX0		29
#define OMAP_DMA_USB_W2FC_TX1		30
#define OMAP_DMA_USB_W2FC_TX2		31

/* These are only for 1610 */
#define OMAP_DMA_CRYPTO_DES_IN		32
#define OMAP_DMA_SPI_TX			33
#define OMAP_DMA_SPI_RX			34
#define OMAP_DMA_CRYPTO_HASH		35
#define OMAP_DMA_CCP_ATTN		36
#define OMAP_DMA_CCP_FIFO_NOT_EMPTY	37
#define OMAP_DMA_CMT_APE_TX_CHAN_0	38
#define OMAP_DMA_CMT_APE_RV_CHAN_0	39
#define OMAP_DMA_CMT_APE_TX_CHAN_1	40
#define OMAP_DMA_CMT_APE_RV_CHAN_1	41
#define OMAP_DMA_CMT_APE_TX_CHAN_2	42
#define OMAP_DMA_CMT_APE_RV_CHAN_2	43
#define OMAP_DMA_CMT_APE_TX_CHAN_3	44
#define OMAP_DMA_CMT_APE_RV_CHAN_3	45
#define OMAP_DMA_CMT_APE_TX_CHAN_4	46
#define OMAP_DMA_CMT_APE_RV_CHAN_4	47
#define OMAP_DMA_CMT_APE_TX_CHAN_5	48
#define OMAP_DMA_CMT_APE_RV_CHAN_5	49
#define OMAP_DMA_CMT_APE_TX_CHAN_6	50
#define OMAP_DMA_CMT_APE_RV_CHAN_6	51
#define OMAP_DMA_CMT_APE_TX_CHAN_7	52
#define OMAP_DMA_CMT_APE_RV_CHAN_7	53
#define OMAP_DMA_MMC2_TX		54
#define OMAP_DMA_MMC2_RX		55
#define OMAP_DMA_CRYPTO_DES_OUT		56


#define OMAP_DMA_BASE			0xfffed800
#define OMAP_DMA_GCR_REG		(OMAP_DMA_BASE + 0x400)
#define OMAP_DMA_GSCR_REG		(OMAP_DMA_BASE + 0x404)
#define OMAP_DMA_GRST_REG		(OMAP_DMA_BASE + 0x408)
#define OMAP_DMA_HW_ID_REG		(OMAP_DMA_BASE + 0x442)
#define OMAP_DMA_PCH2_ID_REG		(OMAP_DMA_BASE + 0x444)
#define OMAP_DMA_PCH0_ID		(OMAP_DMA_BASE + 0x446)
#define OMAP_DMA_PCH1_ID		(OMAP_DMA_BASE + 0x448)
#define OMAP_DMA_PCHG_ID		(OMAP_DMA_BASE + 0x44a)
#define OMAP_DMA_PCHD_ID		(OMAP_DMA_BASE + 0x44c)
#define OMAP_DMA_CAPS_0_U_REG		(OMAP_DMA_BASE + 0x44e)
#define OMAP_DMA_CAPS_0_L_REG		(OMAP_DMA_BASE + 0x450)
#define OMAP_DMA_CAPS_1_U_REG		(OMAP_DMA_BASE + 0x452)
#define OMAP_DMA_CAPS_1_L_REG		(OMAP_DMA_BASE + 0x454)
#define OMAP_DMA_CAPS_2_REG		(OMAP_DMA_BASE + 0x456)
#define OMAP_DMA_CAPS_3_REG		(OMAP_DMA_BASE + 0x458)
#define OMAP_DMA_CAPS_4_REG		(OMAP_DMA_BASE + 0x45a)
#define OMAP_DMA_PCH2_SR_REG		(OMAP_DMA_BASE + 0x460)
#define OMAP_DMA_PCH0_SR_REG		(OMAP_DMA_BASE + 0x480)
#define OMAP_DMA_PCH1_SR_REG		(OMAP_DMA_BASE + 0x482)
#define OMAP_DMA_PCHD_SR_REG		(OMAP_DMA_BASE + 0x4c0)

#define OMAP1510_DMA_LCD_CTRL		0xfffedb00
#define OMAP1510_DMA_LCD_TOP_F1_L	0xfffedb02
#define OMAP1510_DMA_LCD_TOP_F1_U	0xfffedb04
#define OMAP1510_DMA_LCD_BOT_F1_L	0xfffedb06
#define OMAP1510_DMA_LCD_BOT_F1_U	0xfffedb08

#define OMAP1610_DMA_LCD_CSDP		0xfffee3c0
#define OMAP1610_DMA_LCD_CCR		0xfffee3c2
#define OMAP1610_DMA_LCD_CTRL		0xfffee3c4
#define OMAP1610_DMA_LCD_TOP_B1_L	0xfffee3c8
#define OMAP1610_DMA_LCD_TOP_B1_U	0xfffee3ca
#define OMAP1610_DMA_LCD_BOT_B1_L	0xfffee3cc
#define OMAP1610_DMA_LCD_BOT_B1_U	0xfffee3ce
#define OMAP1610_DMA_LCD_TOP_B2_L	0xfffee3d0
#define OMAP1610_DMA_LCD_TOP_B2_U	0xfffee3d2
#define OMAP1610_DMA_LCD_BOT_B2_L	0xfffee3d4
#define OMAP1610_DMA_LCD_BOT_B2_U	0xfffee3d6
#define OMAP1610_DMA_LCD_SRC_EI_B1	0xfffee3d8
#define OMAP1610_DMA_LCD_SRC_FI_B1_L	0xfffee3da
#define OMAP1610_DMA_LCD_SRC_EN_B1	0xfffee3e0
#define OMAP1610_DMA_LCD_SRC_FN_B1	0xfffee3e4
#define OMAP1610_DMA_LCD_LCH_CTRL	0xfffee3ea
#define OMAP1610_DMA_LCD_SRC_FI_B1_U	0xfffee3f4


/* Every LCh has its own set of the registers below */
#define OMAP_DMA_CSDP_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x00)
#define OMAP_DMA_CCR_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x02)
#define OMAP_DMA_CICR_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x04)
#define OMAP_DMA_CSR_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x06)
#define OMAP_DMA_CSSA_L_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x08)
#define OMAP_DMA_CSSA_U_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x0a)
#define OMAP_DMA_CDSA_L_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x0c)
#define OMAP_DMA_CDSA_U_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x0e)
#define OMAP_DMA_CEN_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x10)
#define OMAP_DMA_CFN_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x12)
#define OMAP_DMA_CSFI_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x14)
#define OMAP_DMA_CSEI_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x16)
#define OMAP_DMA_CSAC_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x18)
#define OMAP_DMA_CDAC_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x1a)
#define OMAP_DMA_CDEI_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x1c)
#define OMAP_DMA_CDFI_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x1e)
#define OMAP_DMA_COLOR_L_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x20)
#define OMAP_DMA_COLOR_U_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x22)
#define OMAP_DMA_CCR2_REG(n)		(OMAP_DMA_BASE + 0x40 * (n) + 0x24)
#define OMAP_DMA_CLNK_CTRL_REG(n)	(OMAP_DMA_BASE + 0x40 * (n) + 0x28)
#define OMAP_DMA_LCH_CTRL_REG(n)	(OMAP_DMA_BASE + 0x40 * (n) + 0x2a)

#define OMAP_DMA_TOUT_IRQ		(1 << 0)
#define OMAP_DMA_DROP_IRQ		(1 << 1)
#define OMAP_DMA_HALF_IRQ		(1 << 2)
#define OMAP_DMA_FRAME_IRQ		(1 << 3)
#define OMAP_DMA_LAST_IRQ		(1 << 4)
#define OMAP_DMA_BLOCK_IRQ		(1 << 5)
#define OMAP_DMA_SYNC_IRQ		(1 << 6)

#define OMAP_DMA_DATA_TYPE_S8		0x00
#define OMAP_DMA_DATA_TYPE_S16		0x01
#define OMAP_DMA_DATA_TYPE_S32		0x02

#define OMAP_DMA_SYNC_ELEMENT		0x00
#define OMAP_DMA_SYNC_FRAME		0x01
#define OMAP_DMA_SYNC_BLOCK		0x02

#define OMAP_DMA_PORT_EMIFF		0x00
#define OMAP_DMA_PORT_EMIFS		0x01
#define OMAP_DMA_PORT_OCP_T1		0x02
#define OMAP_DMA_PORT_TIPB		0x03
#define OMAP_DMA_PORT_OCP_T2		0x04
#define OMAP_DMA_PORT_MPUI		0x05

#define OMAP_DMA_AMODE_CONSTANT		0x00
#define OMAP_DMA_AMODE_POST_INC		0x01
#define OMAP_DMA_AMODE_SINGLE_IDX	0x02
#define OMAP_DMA_AMODE_DOUBLE_IDX	0x03

/* LCD DMA block numbers */
enum {
	OMAP_LCD_DMA_B1_TOP,
	OMAP_LCD_DMA_B1_BOTTOM,
	OMAP_LCD_DMA_B2_TOP,
	OMAP_LCD_DMA_B2_BOTTOM
};

extern int omap_request_dma(int dev_id, const char *dev_name,
			    void (* callback)(int lch, u16 ch_status, void *data),
			    void *data, int *dma_ch);
extern void omap_enable_dma_irq(int ch, u16 irq_bits);
extern void omap_disable_dma_irq(int ch, u16 irq_bits);
extern void omap_free_dma(int ch);
extern void omap_start_dma(int lch);
extern void omap_stop_dma(int lch);
extern void omap_set_dma_transfer_params(int lch, int data_type,
					 int elem_count, int frame_count,
					 int sync_mode);
extern void omap_set_dma_src_params(int lch, int src_port, int src_amode,
				    unsigned long src_start);
extern void omap_set_dma_dest_params(int lch, int dest_port, int dest_amode,
				     unsigned long dest_start);

/* Returns 1 if the DMA module is in OMAP1510-compatible mode, 0 otherwise */
extern int omap_dma_in_1510_mode(void);

/* LCD DMA functions */
extern int omap_request_lcd_dma(void (* callback)(u16 status, void *data),
				void *data);
extern void omap_free_lcd_dma(void);
extern void omap_start_lcd_dma(void);
extern void omap_stop_lcd_dma(void);
extern void omap_set_lcd_dma_b1(unsigned long addr, u16 fb_xres, u16 fb_yres,
				int data_type);
extern void omap_set_lcd_dma_b1_rotation(int rotate);

#endif /* __ASM_ARCH_DMA_H */
