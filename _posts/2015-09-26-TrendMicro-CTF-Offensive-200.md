---
layout: post
title: TrendMicro CTF - Offensive 200
category: RE
tags: Exploitation asciinema RE
---

# TrendMicro CTF - Offensive 200
**Points:** 200
**Solves:** 
**Category:** Offensive
**Description:**

> [VirusClicker]({{site.url}}/assets/VirusClicker.apk)

# Write-Up

The Android app pops up a button on the screen and it requires us to press it 10 million times...

![screen]({{site.url}}/assets/Screen Shot 2015-09-27 at 2.17.43 AM.png)

The way I solved this is by patching the smali code and repackaging the apk file. Installing on an emulator only requires us to click 16 times (I chose 16 because it was easier for me to remember the numbers Im patching :).

<p>
<script type="text/javascript" src="https://asciinema.org/a/5qozqtwdocrobyzz0k6jaorhp.js" id="asciicast-5qozqtwdocrobyzz0k6jaorhp" data-speed="2" async></script>
<p>

![screen1]({{site.url}}/assets/Screen Shot 2015-09-27 at 1.49.45 AM.png)

![screen2]({{site.url}}/assets/Screen Shot 2015-09-27 at 1.49.59 AM.png)

If you wonder how I knew which locations to patch. I used www.decompileandroid.com to get the java source code. There I basically followed the flow of execution and made whatever I could from my poor java interpretation.

The java source code of the files that contained important for me data:

{% highlight java %}
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: braces fieldsfirst space lnc 

package com.tm.ctf.clicker.activity;

import android.app.ActionBar;
import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.util.Log;
import com.tm.ctf.clicker.a.a;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

// Referenced classes of package com.tm.ctf.clicker.activity:
//            b

public class CongraturationsActivity extends Activity
{

    private static final String b = com/tm/ctf/clicker/activity/CongraturationsActivity.getSimpleName();
    private static final byte c[] = {
        -119, 80, 78, 71, 13, 10, 26, 10
    };
    b a;

    public CongraturationsActivity()
    {
        a = null;
    }

    private Bitmap a()
    {
        Bitmap bitmap;
        try
        {
            Object obj = getResources().getAssets().open("f.png");
            byte abyte0[] = new byte[((InputStream) (obj)).available()];
            ((InputStream) (obj)).read(abyte0);
            obj = ByteBuffer.allocate(abyte0.length + 8);
            ((ByteBuffer) (obj)).put(c);
            ((ByteBuffer) (obj)).put(abyte0);
            bitmap = BitmapFactory.decodeByteArray(((ByteBuffer) (obj)).array(), 0, abyte0.length + 8);
        }
        catch (IOException ioexception)
        {
            ioexception.printStackTrace();
            return null;
        }
        return bitmap;
    }

    protected void onCreate(Bundle bundle)
    {
        super.onCreate(bundle);
        getActionBar().hide();
        if (0x989680 != com.tm.ctf.clicker.a.a.c())
        {
            finish();
        }
        a = new b(this, (new StringBuilder(String.valueOf(getIntent().getStringExtra("data")))).append("Nf").toString());
        bundle = a();
        setContentView(a);
        Log.i("VirusClicker", (new StringBuilder("width=")).append(bundle.getWidth()).append(", height=").append(bundle.getHeight()).toString());
    }

}
{% endhighlight %}

{% highlight java %}
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: braces fieldsfirst space lnc 

package com.tm.ctf.clicker.activity;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Handler;
import android.os.Message;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import com.tm.ctf.clicker.a.a;

public class c extends SurfaceView
    implements android.view.SurfaceHolder.Callback, Runnable
{

    private Context a;
    private Handler b;
    private SurfaceHolder c;
    private int d;
    private int e;
    private Thread f;
    private int g;
    private boolean h;
    private Bitmap i;
    private Rect j;
    private Bitmap k;
    private Rect l;
    private Bitmap m;
    private Rect n;
    private Bitmap o;
    private Rect p;
    private String q;

    public c(Context context, Handler handler, String s)
    {
        super(context);
        a = null;
        b = null;
        g = 0;
        h = false;
        i = null;
        j = null;
        k = null;
        l = null;
        m = null;
        n = null;
        o = null;
        p = null;
        q = null;
        a = context;
        c = getHolder();
        c.addCallback(this);
        g = 0;
        h = false;
        context = getContext().getResources();
        i = BitmapFactory.decodeResource(context, 0x7f020000);
        j = new Rect(0, 0, i.getWidth(), i.getHeight());
        k = BitmapFactory.decodeResource(context, 0x7f020001);
        l = new Rect(0, 0, k.getWidth(), k.getHeight());
        m = BitmapFactory.decodeResource(context, 0x7f020002);
        n = new Rect(0, 0, m.getWidth(), m.getHeight());
        o = BitmapFactory.decodeResource(context, 0x7f020005);
        p = new Rect(0, 0, o.getWidth(), o.getHeight());
        b = handler;
        q = (new StringBuilder(String.valueOf(s))).append("Z3").toString();
        if (g != com.tm.ctf.clicker.a.a.c())
        {
            context = Message.obtain();
            context.obj = "QUIT";
            b.sendMessage(context);
        }
    }

    private void a(int i1, Canvas canvas, Paint paint)
    {
        int j1;
        int k1;
        k1 = 0;
        j1 = 0;
_L2:
        if (k1 >= 10)
        {
            return;
        }
        int l1 = 0;
        do
        {
label0:
            {
                if (l1 < 10)
                {
                    break label0;
                }
                k1++;
            }
            if (true)
            {
                continue;
            }
            j1++;
            if (j1 > i1)
            {
                Rect rect = new Rect(p);
                rect.offset((d / 11) * (l1 + 1) - rect.right / 2, (e / 11) * (k1 + 1) - rect.bottom / 2);
                canvas.drawBitmap(o, p, rect, paint);
            }
            l1++;
        } while (true);
        if (true) goto _L2; else goto _L1
_L1:
    }

    private void a(int i1, Canvas canvas, Paint paint, Paint paint1)
    {
        String s = Integer.toString(i1);
        i1 = (int)paint.measureText(s);
        String s1 = Integer.toString(0x989680);
        int j1 = (int)paint.measureText(s1);
        canvas.drawText(s, (d - i1) / 2 - 2, (e / 4) * 3, paint1);
        canvas.drawText(s, (d - i1) / 2 + 2, (e / 4) * 3, paint1);
        canvas.drawText(s, (d - i1) / 2, (e / 4) * 3, paint);
        canvas.drawLine((d - j1) / 2, (e / 4) * 3 + 20, (d - j1) / 2 + j1, (e / 4) * 3 + 20, paint);
        canvas.drawText(s1, (d - j1) / 2 - 2, (e / 4) * 3 + 100, paint1);
        canvas.drawText(s1, (d - j1) / 2 + 2, (e / 4) * 3 + 100, paint1);
        canvas.drawText(s1, (d - j1) / 2, (e / 4) * 3 + 100, paint);
    }

    private void a(Canvas canvas, Paint paint, Paint paint1)
    {
        int i1 = (int)paint.measureText("Click Button!");
        canvas.drawText("Click Button!", (d - i1) / 2 - 2, e / 4 - 50, paint1);
        canvas.drawText("Click Button!", (d - i1) / 2 + 2, e / 4 - 50, paint1);
        canvas.drawText("Click Button!", (d - i1) / 2, e / 4 - 50, paint);
        i1 = (int)paint.measureText("Attack Virus!");
        canvas.drawText("Attack Virus!", (d - i1) / 2 - 2, e / 4 + 50, paint1);
        canvas.drawText("Attack Virus!", (d - i1) / 2 + 2, e / 4 + 50, paint1);
        canvas.drawText("Attack Virus!", (d - i1) / 2, e / 4 + 50, paint);
    }

    private void a(boolean flag, Canvas canvas, Paint paint)
    {
        Object obj = i;
        if (flag)
        {
            obj = k;
        }
        Rect rect = new Rect(j);
        rect.offset((d - rect.right) / 2, (e - rect.bottom) / 2);
        canvas.drawBitmap(((Bitmap) (obj)), j, rect, paint);
        obj = new Rect(n);
        ((Rect) (obj)).offset((d - ((Rect) (obj)).right) / 2, (e - ((Rect) (obj)).bottom) / 2);
        canvas.drawBitmap(m, n, ((Rect) (obj)), paint);
    }

    public boolean onTouchEvent(MotionEvent motionevent)
    {
        motionevent.getAction();
        JVM INSTR tableswitch 0 1: default 28
    //                   0 30
    //                   1 37;
           goto _L1 _L2 _L3
_L1:
        return true;
_L2:
        h = true;
        return true;
_L3:
        h = false;
        g = g + 1;
        com.tm.ctf.clicker.a.a.b();
        if (3769 == g || 10007 == g || 59239 == g || 0x186a3 == g || 0x78e75 == g || 0xf4243 == g || 0x98967f == g)
        {
            motionevent = new Intent("com.tm.ctf.clicker.SCORE");
            motionevent.putExtra("SCORE", g);
            a.sendBroadcast(motionevent);
        }
        if (0x989680 <= g)
        {
            motionevent = Message.obtain();
            motionevent.obj = (new StringBuilder(String.valueOf(q))).append("Jh").toString();
            b.sendMessage(motionevent);
            return true;
        }
        if (true) goto _L1; else goto _L4
_L4:
    }

    public void run()
    {
        Paint paint;
        Paint paint1;
        long l1;
        long l3;
        paint = new Paint();
        paint1 = new Paint();
        paint.setStyle(android.graphics.Paint.Style.FILL);
        paint.setColor(0xff000000);
        paint.setTextSize(80F);
        paint1.setStyle(android.graphics.Paint.Style.FILL);
        paint1.setColor(-1);
        paint1.setTextSize(80F);
        l3 = System.currentTimeMillis();
        l1 = 0L;
_L2:
        long l2;
        if (f == null)
        {
            return;
        }
        l2 = l1 + 1L;
        long l4;
        Canvas canvas = c.lockCanvas();
        canvas.drawPaint(paint1);
        a(g % 100, canvas, paint);
        a(canvas, paint, paint1);
        a(g, canvas, paint, paint1);
        a(h, canvas, paint1);
        c.unlockCanvasAndPost(canvas);
        l4 = 16L * l2 - (System.currentTimeMillis() - l3);
        l1 = l2;
        if (l4 <= 0L)
        {
            continue; /* Loop/switch isn't completed */
        }
        Thread.sleep(l4);
        l1 = l2;
        continue; /* Loop/switch isn't completed */
        Exception exception;
        exception;
        l1 = l2;
        if (true) goto _L2; else goto _L1
_L1:
    }

    public void surfaceChanged(SurfaceHolder surfaceholder, int i1, int j1, int k1)
    {
        d = j1;
        e = k1;
    }

    public void surfaceCreated(SurfaceHolder surfaceholder)
    {
        f = new Thread(this);
        f.start();
    }

    public void surfaceDestroyed(SurfaceHolder surfaceholder)
    {
        if (!f.isInterrupted())
        {
            f.interrupt();
        }
        f = null;
    }
}
{% endhighlight %}

{% highlight java %}
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: braces fieldsfirst space lnc 

package com.tm.ctf.clicker.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.tm.ctf.clicker.a.a;

public class ScoreBroadcastReceiver extends BroadcastReceiver
{

    public ScoreBroadcastReceiver()
    {
    }

    public void onReceive(Context context, Intent intent)
    {
        int i;
        i = intent.getIntExtra("SCORE", 0);
        context = "";
        if (3769 != i) goto _L2; else goto _L1
_L1:
        context = "2";
_L4:
        a.a(context);
        return;
_L2:
        if (10007 == i)
        {
            context = "x";
        } else
        if (59239 == i)
        {
            context = "p";
        } else
        if (0x186a3 == i)
        {
            context = "Y";
        } else
        if (0x78e75 == i)
        {
            context = "2";
        } else
        if (0xf4243 == i)
        {
            context = "t";
        } else
        if (0x98967f == i)
        {
            context = "z";
        }
        if (true) goto _L4; else goto _L3
_L3:
    }
}
{% endhighlight %}

* Thank you for reading/watching ;)