      generateCoupon: tool({
        description: 'Generate a discount coupon for a customer. Only use this when the coupon policy conditions are fully met.',
        inputSchema: z.object({
          discount: z.number().int().min(COUPON_DISCOUNT).max(COUPON_DISCOUNT).describe(`The discount percentage for the coupon (always ${COUPON_DISCOUNT})`),
          orderId: z.string().describe('The order ID of the damaged order (format: xxxx-xxxxxxxxxxxxxxxx)')
        }),
        execute: async ({ discount, orderId }) => {
          if (discount !== COUPON_DISCOUNT) return { error: `Coupons are only available with a ${COUPON_DISCOUNT}% discount` }
          const eligibility = await couponEligibleOrder(req, orderId)
          if (eligibility.error) return eligibility
          const couponCode = security.generateCoupon(discount)
          return { couponCode, discount }
        }
      }),

      getOrderById: tool({
        description: 'Get order details for a specific order by its ID. Only returns the order if it belongs to the current customer.',
        inputSchema: z.object({
          orderId: z.string().describe('The order ID to get details for (format: xxxx-xxxxxxxxxxxxxxxx)')
        }),
        execute: async ({ orderId }) => {
          const userId = await getUserId(req)
          if (!userId) return { error: 'Customer not authenticated' }

          const user = await UserModel.findByPk(userId, { attributes: ['email'] })
          if (!user) return { error: 'Customer not found' }

          const order = await db.ordersCollection.findOne({ orderId })

          if (!order) return { error: 'Order not found' }
          if (order.email !== user.email) return { error: 'Order does not belong to the current customer' }

          return order
        }
      })
    }