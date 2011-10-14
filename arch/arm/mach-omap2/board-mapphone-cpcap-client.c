/*
 * arch/arm/mach-omap2/board-mapphone-cpcap-client.c
 *
 * Copyright (C) 2009-2010 Motorola, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/spi/cpcap.h>
#include <linux/leds-ld-cpcap.h>
#include <linux/leds-ld-cpcap-disp.h>
#include <linux/leds-cpcap-kpad.h>
#include <linux/leds-cpcap-display.h>
#include <linux/leds-cpcap-button.h>
#include <linux/cpcap_audio_platform_data.h>
#include <linux/pm_dbg.h>
#include <mach/gpio.h>
#include <plat/mux.h>
#include <plat/resource.h>
#include <plat/omap34xx.h>

#ifdef CONFIG_ARM_OF
#include <mach/dt_path.h>
#include <asm/prom.h>
#endif
/*
 * CPCAP devcies are common for different HW Rev.
 *
 */
static struct platform_device cpcap_3mm5_device = {
	.name   = "cpcap_3mm5",
	.id     = -1,
	.dev    = {
		.platform_data  = NULL,
	},
};

#ifdef CONFIG_CPCAP_USB
static struct platform_device cpcap_usb_device = {
	.name           = "cpcap_usb",
	.id             = -1,
	.dev.platform_data = NULL,
};

static struct platform_device cpcap_usb_det_device = {
	.name   = "cpcap_usb_det",
	.id     = -1,
	.dev    = {
		.platform_data  = NULL,
	},
};
#endif /* CONFIG_CPCAP_USB */

#ifdef CONFIG_TTA_CHARGER
static struct platform_device cpcap_tta_det_device = {
	.name   = "cpcap_tta_charger",
	.id     = -1,
	.dev    = {
		.platform_data  = NULL,
	},
};
#endif


static struct platform_device cpcap_rgb_led = {
	.name           = LD_MSG_IND_DEV,
	.id             = -1,
	.dev.platform_data  = NULL,
};

#ifdef CONFIG_SOUND_CPCAP_OMAP
static struct platform_device cpcap_audio_device = {
	.name           = "cpcap_audio",
	.id             = -1,
	.dev.platform_data  = NULL,
};
#endif

#ifdef CONFIG_LEDS_AF_LED
static struct platform_device cpcap_af_led = {
	.name           = LD_AF_LED_DEV,
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
       },
};
#endif

static struct platform_device cpcap_bd7885 = {
	.name           = "bd7885",
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
       },
};

static struct platform_device cpcap_vio_active_device = {
	.name		= "cpcap_vio_active",
	.id		= -1,
	.dev		= {
		.platform_data = NULL,
	},
};

#ifdef CONFIG_PM_DBG_DRV
static struct platform_device cpcap_pm_dbg_device = {
	.name		= "cpcap_pm_dbg",
	.id		= -1,
	.dev		= {
		.platform_data = NULL,
	},
};

static struct pm_dbg_drvdata cpcap_pm_dbg_drvdata = {
	.pm_cd_factor = 1000,
};
#endif

static struct platform_device *cpcap_devices[] = {
#ifdef CONFIG_CPCAP_USB
	&cpcap_usb_device,
	&cpcap_usb_det_device,
#endif
#ifdef CONFIG_SOUND_CPCAP_OMAP
	&cpcap_audio_device,
#endif
	&cpcap_3mm5_device,
#ifdef CONFIG_TTA_CHARGER
	&cpcap_tta_det_device,
#endif
#ifdef CONFIG_LEDS_AF_LED
	&cpcap_af_led,
#endif
	&cpcap_bd7885
};


/*
 * CPCAP devcies whose availability depends on HW
 *
 */
static struct platform_device  cpcap_kpad_led = {
	.name           = CPCAP_KPAD_DEV,
	.id             = -1,
	.dev            = {
	.platform_data  = NULL,
	},
};

static struct platform_device ld_cpcap_kpad_led = {
	.name           = LD_KPAD_DEV,
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
	},
};

static struct platform_device cpcap_button_led = {
	.name           = CPCAP_BUTTON_DEV,
	.id             = -1,
	.dev            = {
	.platform_data  = NULL,
	},
};

static struct disp_button_config_data btn_data;

static struct platform_device ld_cpcap_disp_button_led = {
	.name           = LD_DISP_BUTTON_DEV,
	.id             = -1,
	.dev            = {
	.platform_data  = &btn_data,
	},
};

static struct platform_device cpcap_display_led = {
	.name           = CPCAP_DISPLAY_DRV,
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
	},
};

static struct platform_device cpcap_lm3554 = {
	.name           = "flash-torch",
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
	},
};

static struct platform_device cpcap_lm3559 = {
	.name           = "flash-torch-3559",
	.id             = -1,
	.dev            = {
		.platform_data  = NULL,
	},
};

#ifdef CONFIG_ARM_OF
static int __init is_ld_cpcap_kpad_on(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_KPAD_LED);
	if (node == NULL) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_KPAD_LED);
		return -ENODEV;
	}

	prop = of_get_property(node, "tablet_kpad_led", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", DT_PROP_TABLET_KPAD_LED);
			of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init is_cpcap_kpad_on(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_KPAD_LED);
	if (node == NULL) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_KPAD_LED);
		return -ENODEV;
	}

	prop = of_get_property(node, "ruth_kpad_led", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", DT_PROP_RUTH_KPAD_LED);
		of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init cpcap_button_init(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_HOME_LED);
	if (node == NULL) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_HOME_LED);
		return -ENODEV;
}

	prop = of_get_property(node, "ruth_button_led", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", DT_PROP_RUTH_BUTTON);
			of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init ld_cpcap_disp_button_init(void)
{
	struct disp_button_config_data *pbtn_data = &btn_data;
	u8 device_available, ret;

	ret = -ENODEV;

        device_available = 1;
        pbtn_data->duty_cycle = 0xB8;
	pbtn_data->cpcap_mask = 0x3FF;
	pbtn_data->led_current =  0x0;
	pbtn_data->reg = CPCAP_REG_BLEDC;

	ret = 1;
	return ret;
}

static int __init is_disp_led_on(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_BACKLIGHT);
	if (node == NULL) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_BACKLIGHT);
		return -ENODEV;
	}

	prop = of_get_property(node, "ruth_lcd", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", DT_PROP_RUTH_LCD);
			of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init led_cpcap_lm3554_init(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_PATH_LM3554);
	if (node == NULL)
		return -ENODEV;

	prop = of_get_property(node, "device_available", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", "device_available");
		of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init led_cpcap_lm3559_init(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_PATH_LM3559);
	if (node == NULL)
		return -ENODEV;

	prop = of_get_property(node, "device_available", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", "device_available");
		of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

static int __init is_ld_cpcap_rgb_on(void)
{
	u8 device_available;
	struct device_node *node;
	const void *prop;

	node = of_find_node_by_path(DT_NOTIFICATION_LED);
	if (node == NULL) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_NOTIFICATION_LED);
		return -ENODEV;
	}

	prop = of_get_property(node, "tablet_rgb_led", NULL);
	if (prop)
		device_available = *(u8 *)prop;
	else {
		pr_err("Read property %s error!\n", DT_PROP_TABLET_RGB_LED);
		of_node_put(node);
		return -ENODEV;
	}

	of_node_put(node);
	return device_available;
}

int is_cpcap_vio_supply_converter(void)
{
	struct device_node *node;
	const void *prop;
	int size;

	node = of_find_node_by_path(DT_PATH_CPCAP);
	if (node) {
		prop = of_get_property(node,
				DT_PROP_CPCAP_VIO_SUPPLY_CONVERTER,
				&size);
		if (prop && size)
			return *(u8 *)prop;
	}
	/* The converter is existing by default */
	return 1;
}

#ifdef CONFIG_SOUND_CPCAP_OMAP
static void get_cpcap_audio_data(void)
{
	struct device_node *node;
	const void *prop;
	static struct cpcap_audio_pdata data;

	cpcap_audio_device.dev.platform_data = (void *)&data;

	node = of_find_node_by_path(DT_PATH_AUDIO);
	if (!node) {
		pr_err("Unable to read node %s from device tree!\n",
			DT_PATH_AUDIO);
		return;
	}

	prop = of_get_property(node, DT_PROP_AUDIO_ANALOG_DOWNLINK, NULL);
	if (prop)
		data.analog_downlink = (*(int *)prop > 0 ? 1 : 0);
	else {
		data.analog_downlink = 0;
		pr_err("Read property %s error!\n",
			DT_PROP_AUDIO_ANALOG_DOWNLINK);
	}

	prop = of_get_property(node, DT_PROP_AUDIO_STEREO_LOUDSPEAKER, NULL);
	if (prop)
		data.stereo_loudspeaker = (*(int *)prop > 0 ? 1 : 0);
	else {
		data.stereo_loudspeaker = 0;
		pr_err("Read property %s error!\n",
			DT_PROP_AUDIO_STEREO_LOUDSPEAKER);
	}

	prop = of_get_property(node, DT_PROP_AUDIO_MIC3, NULL);
	if (prop)
		data.mic3 = (*(int *)prop > 0 ? 1 : 0);
	else {
		data.mic3 = 0;
		pr_err("Read property %s error!\n",
			DT_PROP_AUDIO_MIC3);
	}
	prop = of_get_property(node, DT_PROP_AUDIO_I2S_BP, NULL);
	if (prop)
		data.i2s_bp = (*(int *)prop > 0 ? 1 : 0);
	else {
		data.i2s_bp = 0;
		pr_err("Read property %s error!\n",
			DT_PROP_AUDIO_I2S_BP);
	}

	prop = of_get_property(node, DT_PROP_AUDIO_MB_BIAS, NULL);
	if (prop) {
		/* MB_BIAS_R[1:0]
		::: 00 : 0Ohm / 01 : 2.2KOhm
		::: 10 : 4.7KOhm / 11 : invalid state */
		data.mb_bias = *(int *)prop;
		if (data.mb_bias < 0 || data.mb_bias > 2)
			data.mb_bias = 0;
	} else {
		data.mb_bias = 0;
		pr_err("Read property %s error!\n",
			DT_PROP_AUDIO_MB_BIAS);
	}

	of_node_put(node);
}
#endif

#ifdef CONFIG_PM_DBG_DRV
static void get_pm_dbg_drvdata(void)
{
	struct device_node *node;
	const void *prop;
	int size;

	node = of_find_node_by_path("/System@0/PMDbgDevice@0");
	if (node) {
		prop = of_get_property(node,
			"pm_cd_factor",
			&size);
		if (prop && size)
			cpcap_pm_dbg_drvdata.pm_cd_factor = *(u16 *)prop;
	}
}
#endif

#endif /* CONFIG_ARM_OF */


void __init mapphone_cpcap_client_init(void)
{
	int i;

#ifdef CONFIG_SOUND_CPCAP_OMAP
	get_cpcap_audio_data();
#endif

	for (i = 0; i < ARRAY_SIZE(cpcap_devices); i++)
		cpcap_device_register(cpcap_devices[i]);

	if (is_cpcap_kpad_on() > 0)
		cpcap_device_register(&cpcap_kpad_led);

	if (is_ld_cpcap_kpad_on() > 0)
		cpcap_device_register(&ld_cpcap_kpad_led);

	if (ld_cpcap_disp_button_init() > 0)
		cpcap_device_register(&ld_cpcap_disp_button_led);

	if (cpcap_button_init() > 0)
		cpcap_device_register(&cpcap_button_led);

	if (is_disp_led_on() > 0)
		cpcap_device_register(&cpcap_display_led);

	if (led_cpcap_lm3554_init() > 0)
		cpcap_device_register(&cpcap_lm3554);

	if (led_cpcap_lm3559_init() > 0)
		cpcap_device_register(&cpcap_lm3559);

	if (is_ld_cpcap_rgb_on() > 0)
		cpcap_device_register(&cpcap_rgb_led);

	if (!is_cpcap_vio_supply_converter())
		cpcap_device_register(&cpcap_vio_active_device);

#ifdef CONFIG_PM_DBG_DRV
	get_pm_dbg_drvdata();
	cpcap_device_register(&cpcap_pm_dbg_device);
	platform_set_drvdata(&cpcap_pm_dbg_device, &cpcap_pm_dbg_drvdata);
#endif
}
