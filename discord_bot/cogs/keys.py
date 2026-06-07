import discord
from discord.ext import commands
import requests
import json
from config import API_BASE_URL, ADMIN_KEY


class Keys(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.api = API_BASE_URL

    def _api_post(self, endpoint: str, data: dict):
        try:
            r = requests.post(f"{self.api}{endpoint}", json=data, timeout=10)
            return r.json()
        except Exception as e:
            return {"success": False, "message": f"API error: {e}"}

    def _api_get(self, endpoint: str, params: dict = None):
        try:
            r = requests.get(f"{self.api}{endpoint}", params=params, timeout=10)
            return r.json()
        except Exception as e:
            return {"success": False, "message": f"API error: {e}"}

    @commands.command(name="genkey", aliases=["generate"])
    @commands.has_permissions(administrator=True)
    async def gen_key(self, ctx, count: int = 1, days: int = 30):
        """Generate license keys. Usage: !genkey [count] [days]"""
        result = self._api_post("/api/license/generate", {
            "count": count,
            "expiry_days": days
        })
        if result.get("success"):
            keys = result.get("keys", [])
            msg = f"**Generated {len(keys)} keys** ({days}d expiry):\n"
            for k in keys:
                msg += f"`{k['license_key']}`\n"
            if len(msg) > 2000:
                parts = [msg[i:i+1900] for i in range(0, len(msg), 1900)]
                for p in parts:
                    await ctx.send(p)
            else:
                await ctx.send(msg)
        else:
            await ctx.send(f"❌ {result.get('message', 'Failed')}")

    @commands.command(name="keyinfo", aliases=["license"])
    async def key_info(self, ctx, license_key: str):
        """Check license key info. Usage: !keyinfo LICENSE-KEY-HERE"""
        result = self._api_get("/api/license/info", {"license_key": license_key})
        if result.get("success"):
            embed = discord.Embed(title="License Key Info", color=discord.Color.blue())
            embed.add_field(name="Key", value=f"`{result['license_key']}`", inline=False)
            embed.add_field(name="Status", value="🔴 Banned" if result["banned"] else "🟢 Active", inline=True)
            embed.add_field(name="HWID Locked", value="✅ Yes" if result["hwid_locked"] else "❌ No", inline=True)
            embed.add_field(name="Expires", value=result["expires"], inline=True)
            embed.add_field(name="Created", value=result.get("created_at", "N/A"), inline=True)
            embed.add_field(name="Last Login", value=result.get("last_login", "Never"), inline=True)
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ {result.get('message', 'Not found')}")

    @commands.command(name="ban")
    @commands.has_permissions(administrator=True)
    async def ban_key(self, ctx, license_key: str):
        """Ban a license key. Usage: !ban LICENSE-KEY"""
        result = self._api_post("/api/license/ban", {
            "license_key": license_key,
            "admin_key": ADMIN_KEY,
            "ban": True
        })
        if result.get("success"):
            await ctx.send(f"✅ License `{license_key}` has been banned.")
        else:
            await ctx.send(f"❌ {result.get('message', 'Failed')}")

    @commands.command(name="unban")
    @commands.has_permissions(administrator=True)
    async def unban_key(self, ctx, license_key: str):
        """Unban a license key. Usage: !unban LICENSE-KEY"""
        result = self._api_post("/api/license/ban", {
            "license_key": license_key,
            "admin_key": ADMIN_KEY,
            "ban": False
        })
        if result.get("success"):
            await ctx.send(f"✅ License `{license_key}` has been unbanned.")
        else:
            await ctx.send(f"❌ {result.get('message', 'Failed')}")

    @commands.command(name="resethwid")
    @commands.has_permissions(administrator=True)
    async def reset_hwid(self, ctx, license_key: str):
        """Reset HWID lock on a key. Usage: !resethwid LICENSE-KEY"""
        result = self._api_post("/api/reset", {
            "license": license_key,
            "admin_key": ADMIN_KEY
        })
        if result.get("success"):
            await ctx.send(f"✅ HWID reset for `{license_key}`.")
        else:
            await ctx.send(f"❌ {result.get('message', 'Failed')}")


async def setup(bot):
    await bot.add_cog(Keys(bot))
