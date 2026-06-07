import discord
from discord.ext import commands
import requests
from config import API_BASE_URL, ADMIN_KEY


class Admin(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.api = API_BASE_URL

    @commands.command(name="stats")
    @commands.has_permissions(administrator=True)
    async def server_stats(self, ctx):
        """Show server statistics"""
        try:
            r = requests.get(f"{self.api}/", timeout=5)
            data = r.json()
            embed = discord.Embed(
                title="KeyAuth Server Status",
                description=f"Service: {data.get('service', 'N/A')}",
                color=discord.Color.green()
            )
            embed.add_field(name="Version", value=data.get("version", "N/A"))
            endpoints = data.get("endpoints", {})
            eps = "\n".join([f"`{v}`" for v in endpoints.values()])
            embed.add_field(name="Endpoints", value=eps[:1024], inline=False)
            await ctx.send(embed=embed)
        except Exception as e:
            await ctx.send(f"❌ Cannot reach API: {e}")

    @commands.command(name="shutdown")
    @commands.has_permissions(administrator=True)
    async def shutdown_bot(self, ctx):
        """Shutdown the Discord bot"""
        await ctx.send("👋 Shutting down...")
        await self.bot.close()


async def setup(bot):
    await bot.add_cog(Admin(bot))
